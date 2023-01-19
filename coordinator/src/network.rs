use std::{collections::HashMap, time::Duration, env, io, fmt, str};
use group::ff::PrimeField;
use message_box::{MessageBox, PublicKey};
use tokio::{sync::mpsc, signal::ctrl_c};
use serde::{Deserialize, Serialize};
use log::{error, info};
use futures::StreamExt;
use libp2p::{
  core::{upgrade},
  floodsub::{Floodsub, FloodsubEvent, Topic},
  identity::{self},
  mplex,
  noise::{Keypair, NoiseConfig, X25519Spec},
  swarm::NetworkBehaviourEventProcess,
  tcp::TcpConfig,
  NetworkBehaviour, PeerId, Swarm, Transport, Multiaddr,
};

use rdkafka::{
  consumer::{BaseConsumer, Consumer},
  ClientConfig, Message,
  producer::{BaseProducer, BaseRecord, Producer},
};

use dns_lookup::lookup_host;
use crate::{
  core::ChainConfig,
  core::KafkaConfig,
  signature::{SignatureMessageType, parse_message_type, Coin, create_coin_hashmap},
};

use std::sync::mpsc::{Sender, Receiver};

// Used when a consumer needs to communicate the coordinators own processor pubkeys through a channel.
// The receiver for the channel will then communicate the pubkeys to the other coordinators.
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct ProcessorChannelMessage {
  signer: String,
  coin: String,
  pubkey: String,
}

// Represents the type of message being sent
#[derive(Serialize, Deserialize, Debug, Clone)]
pub enum NetworkMessageType {
  // State of connected Signers
  NetworkState,
  // Coordinator Pubkey Message
  CoordinatorPubkey,
  // Message Box Secure Message for Coordinator
  CoordinatorSecure,
  // Processor Pubkey Message
  ProcessorPubkey,
}

// A message or event generated by a signer.
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct NetworkMessage {
  // The type of message this is.
  pub message_type: NetworkMessageType,
  // The data contained within the message, represented as a vector of bytes.
  pub data: Vec<u8>,
  // The intended recipient of the message, a Signer p2p address encoded as a string.
  pub receiver_p2p_address: Option<String>,
  // The sender of this message, Signer p2p address encoded as a String
  pub sender_p2p_address: String,
}

// Contains the currently connected signers and their public keys.
#[derive(Serialize, Deserialize, Debug)]
pub struct NetworkState {
  // The signers currently connected to the network.
  pub signers: HashMap<String, String>,
  pub signer_coordinator_pubkeys: HashMap<String, String>,
  pub kafka_config: KafkaConfig,
}

impl NetworkState {
  // Attempt to merge two states together.
  pub fn merge(&mut self, mut other: NetworkState) {
    // Merge signers.
    for (signer_address, signer_name) in other.signers.drain() {
      if !self.signers.contains_key(&signer_address) {
        info!("Connected with signer: {}", &signer_name);
        self.signers.insert(signer_address, signer_name);
      }
    }
  }

  // Attempt to collect the name of a signer, if the signer doesn't exist then the name
  // defaults to `anon`.
  pub fn get_signer_name(&self, signer: &String) -> String {
    self.signers.get(signer).unwrap_or(&String::from("anon")).to_string()
  }
}

// The network behavior for swarm.
#[derive(NetworkBehaviour)]
#[behaviour(event_process = true)]
struct NetworkConnection {
  floodsub: Floodsub,
  #[behaviour(ignore)]
  network_state: NetworkState,
  #[behaviour(ignore)]
  signer_p2p_address: String,
  #[behaviour(ignore)]
  responder: mpsc::UnboundedSender<NetworkMessage>,
}

// Fires event when a message is received.
impl NetworkBehaviourEventProcess<FloodsubEvent> for NetworkConnection {
  fn inject_event(&mut self, event: FloodsubEvent) {
    match event {
      FloodsubEvent::Message(raw_data) => {
        // Parse the message as bytes
        let deser = bincode::deserialize::<NetworkMessage>(&raw_data.data);
        if let Ok(message) = deser {
          if let Some(user) = &message.receiver_p2p_address {
            if *user != self.signer_p2p_address.to_string() {
              return; //Don't process messages not intended for us.
            }
          }

          match message.message_type {
            // On connection the network state is merged with the signers network state.
            NetworkMessageType::NetworkState => {
              info!("Network State Received!");
              let data: NetworkState = bincode::deserialize(&message.data).unwrap();
              self.network_state.merge(data);
            }
            // Coordinator has received a signers coordinator pubkey used for message box.
            NetworkMessageType::CoordinatorPubkey => {
              let sender: String = self.network_state.get_signer_name(&raw_data.source.to_string());
              let pubkey = String::from_utf8_lossy(&message.data);
              info!("Coordinator Pubkey recieved! {}: {}", sender, pubkey);
              self.network_state.signer_coordinator_pubkeys.insert(sender, pubkey.to_string());
            }
            // Coordinator has received a secure message from a signer.
            NetworkMessageType::CoordinatorSecure => {
              let sender: String = self.network_state.get_signer_name(&raw_data.source.to_string());
              let secure_message = String::from_utf8_lossy(&message.data);
              info!("Secure Message recieved! {}: {}", sender, secure_message);

              let reciever_name: String =
                self.network_state.get_signer_name(&self.signer_p2p_address);
              let pubkey_string =
                &self.network_state.signer_coordinator_pubkeys.get(&sender).unwrap().to_string();
              let signer_pubkey = message_box::PublicKey::from_trusted_str(pubkey_string);
              let _decoded_msg = decrypt_secure_msg(&reciever_name, &secure_message, signer_pubkey);
            }
            // Coordinator has received a secure message containing a processor pubkey from a signer.
            NetworkMessageType::ProcessorPubkey => {
              // Create Producer to communicate processor pubkey with Kafka
              info!("Secure Processor Pubkey recieved!");
              let sender: String = self.network_state.get_signer_name(&raw_data.source.to_string());
              let secure_message = String::from_utf8_lossy(&message.data);

              let reciever_name: String =
                self.network_state.get_signer_name(&self.signer_p2p_address);
              let pubkey_string =
                &self.network_state.signer_coordinator_pubkeys.get(&sender).unwrap().to_string();
              let signer_pubkey = message_box::PublicKey::from_trusted_str(pubkey_string);
              let decoded_msg = decrypt_secure_msg(&reciever_name, &secure_message, signer_pubkey);
              let processor_channel_message: ProcessorChannelMessage =
                serde_json::from_str(decoded_msg.as_str()).unwrap();

              // Creates a producer to send processor pubkey message
              let producer: BaseProducer<_> = ClientConfig::new()
                .set(
                  "bootstrap.servers",
                  format!(
                    "{}:{}",
                    self.network_state.kafka_config.host, self.network_state.kafka_config.port
                  ),
                )
                .create()
                .expect("invalid producer config");

              // Sends message to Kafka
              producer
                .send(
                  BaseRecord::to(&format!(
                    "{}_processor_{}",
                    &processor_channel_message.signer,
                    &processor_channel_message.coin.to_string().to_lowercase()
                  ))
                  .key(&format!("{}", SignatureMessageType::ProcessorPubkeyToProcessor.to_string()))
                  .payload(&processor_channel_message.pubkey)
                  .partition(0),
                )
                .expect("failed to send message");

              // Flushes producer
              producer.flush(Duration::from_secs(10));
            }
          }
        } else {
          error!("Unable to decode message! Due to {:?}", deser.unwrap_err());
        }
      }
      FloodsubEvent::Subscribed { peer_id, topic: _ } => {
        // Send our state to new user
        // info!("Sending stage to {}", peer_id);
        let message: NetworkMessage = NetworkMessage {
          message_type: NetworkMessageType::NetworkState,
          data: bincode::serialize(&self.network_state).unwrap(),
          receiver_p2p_address: Some(peer_id.to_string()),
          sender_p2p_address: self.signer_p2p_address.to_string(),
        };
        send_response(message, self.responder.clone());
      }
      FloodsubEvent::Unsubscribed { peer_id, topic: _ } => {
        // After a signers disconnects, remove them from the network state.
        let name =
          self.network_state.signers.remove(&peer_id.to_string()).unwrap_or(String::from("Anon"));
        let signer_ref: String = self.network_state.get_signer_name(&peer_id.to_string());
        self
          .network_state
          .signer_coordinator_pubkeys
          .remove(&signer_ref.to_string())
          .unwrap_or(String::from("Anon"));
        info!("Disconnect from {}", name);
      }
    }
  }
}

// Network Process contains our signer's name, address, & address book for other signers.
#[derive(Clone, Debug, Deserialize)]
pub struct NetworkProcess {
  signer_name: String,
  signer_ipv4_address: String,
  ipv4_addresses: HashMap<String, String>,
}

impl NetworkProcess {
  // Builds a address book of ipv4 addresses based on hostnames of signers.
  pub fn new(signer_name: String, signers: Vec<config::Value>) -> Self {
    info!("New Network Process");

    let mut hostname = "".to_string();
    hostname.push_str("coordinator-");
    hostname.push_str(&signer_name);
    let ips: Vec<std::net::IpAddr> = lookup_host(&hostname).unwrap();
    let ip = ips[0].to_string();

    let mut signers_address_ref = "/ip4/".to_string();
    signers_address_ref.push_str(ip.as_str());
    signers_address_ref.push_str("/tcp/8080");

    let mut address_book_ref: HashMap<String, String> = HashMap::new();

    for signer in signers {
      let name_ref = signer.into_string().unwrap();
      if name_ref != signer_name {
        let hostname_ref = format!("coordinator-{}", &name_ref);
        let ips_ref_result = lookup_host(&hostname_ref);
        if !ips_ref_result.is_err() {
          let ips_ref = ips_ref_result.unwrap();
          let ip_ref = ips_ref[0].to_string();

          let mut address_string = "/ip4/".to_string();
          address_string.push_str(ip_ref.as_str());
          address_string.push_str("/tcp/8080");
          address_book_ref.insert(name_ref, address_string);
        }
      }
    }

    Self { signer_name, signer_ipv4_address: signers_address_ref, ipv4_addresses: address_book_ref }
  }

  // Runs network process & listens for events.
  pub async fn run(self, chain_config: ChainConfig, kafka_config: KafkaConfig) {
    info!("Starting Network Process");

    // Initialize Pub/Priv key pair
    initialize_keys(&self.signer_name);

    // Boiler plate code for setting up libp2p network.
    let id_keys = identity::Keypair::generate_ed25519();
    let signer_p2p_address = PeerId::from(id_keys.public());

    let auth_keys = Keypair::<X25519Spec>::new()
      .into_authentic(&id_keys)
      .expect("unable to create authenticated keys");

    let transport = TcpConfig::new()
      .upgrade(upgrade::Version::V1)
      .authenticate(NoiseConfig::xx(auth_keys).into_authenticated())
      .multiplex(mplex::MplexConfig::new())
      .boxed();

    // Generate network channel for p2p communicaton
    let (response_sender, mut response_rcv) = mpsc::unbounded_channel();

    // Create network behaviour using floodsub to broadcast messages.
    let mut behaviour = NetworkConnection {
      floodsub: Floodsub::new(signer_p2p_address),
      network_state: NetworkState {
        signers: HashMap::from([(signer_p2p_address.to_string(), self.signer_name.to_string())]),
        signer_coordinator_pubkeys: HashMap::new(),
        kafka_config: kafka_config.clone(),
      },
      signer_p2p_address: signer_p2p_address.to_string(),
      responder: response_sender,
    };

    // Create a topic for libp2p channel
    let topic = Topic::new("coordinator");
    behaviour.floodsub.subscribe(topic.clone());

    // Create Swarm
    let mut swarm = Swarm::new(transport, behaviour, signer_p2p_address);
    let listening_address: Multiaddr = self.signer_ipv4_address.parse().unwrap();
    swarm.listen_on(listening_address).unwrap();

    // Dial all other signers
    for (_name, address) in self.ipv4_addresses {
      let address_ref = address.parse::<Multiaddr>().unwrap();
      swarm.dial(address_ref).unwrap();
    }

    // Create channel for kafka consumer to relay processor pubkeys to p2p network
    let (tx, rx): (Sender<ProcessorChannelMessage>, Receiver<ProcessorChannelMessage>) =
      std::sync::mpsc::channel();

    // Create coin hashmap used for kafka consumers
    let coin_hashmap = create_coin_hashmap(&chain_config);

    // Create kafka consumers for processor pubkeys
    create_processor_consumers(&kafka_config, &self.signer_name, &coin_hashmap, tx);

    // Add our own signer pubkey to the signer pubkey hashmap
    // This is initially used when our network state is merged with the other signers
    let mut sender_name = self.signer_name.clone().to_uppercase();
    sender_name.push_str("_PUB");
    let pubkey_string = env::var(sender_name).unwrap().to_string();
    swarm
      .behaviour_mut()
      .network_state
      .signer_coordinator_pubkeys
      .insert(self.signer_name.clone(), pubkey_string);

    loop {
      if &swarm.behaviour_mut().network_state.signers.len()
        == &swarm.behaviour_mut().network_state.signer_coordinator_pubkeys.len()
        && swarm.behaviour_mut().network_state.signers.len() > 1
      {
        // Add small delay for kafka to process message.
        tokio::time::sleep(Duration::from_millis(500)).await;
        for processor_msg in rx.try_iter() {
          // Send Network Message to other Coordinator with updated pubkey
          let signer_pubkeys =
            swarm.behaviour_mut().network_state.signer_coordinator_pubkeys.clone();
          for (sender_name, sender_pubkey_string) in signer_pubkeys {
            if sender_name != self.signer_name {
              let decoded_msg = serde_json::to_string(&processor_msg).unwrap();
              let sender_pubkey = message_box::PublicKey::from_trusted_str(&sender_pubkey_string);
              let enc_msg =
                build_secure_msg(&self.signer_name.clone(), sender_pubkey, &decoded_msg);

              let receiver_p2p_address = swarm
                .behaviour_mut()
                .network_state
                .signers
                .iter()
                .find(|(_, name)| name.to_owned() == &sender_name)
                .unwrap()
                .0
                .to_string();

              let message = NetworkMessage {
                message_type: NetworkMessageType::ProcessorPubkey,
                data: enc_msg.as_bytes().to_vec(),
                receiver_p2p_address: Some(receiver_p2p_address.to_string()),
                sender_p2p_address: signer_p2p_address.to_string(),
              };

              send_message(&message, &mut swarm, &topic);
            }
          }
        }
      }

      tokio::select! {
        _ = network_tick() => {
          // This tick is used to trigger sending messages after a connection is established
          // Sending messages immdediatly after connection is established without a tick causes the messages to be dropped
          // Check if we need to communicate pubkey to new signers
          if &swarm.behaviour_mut().network_state.signers.len() > &swarm.behaviour_mut().network_state.signer_coordinator_pubkeys.len() {
            let signers = swarm.behaviour_mut().network_state.signers.clone();
            let signer_pubkeys = swarm.behaviour_mut().network_state.signer_coordinator_pubkeys.clone();
            for (signer_p2p_address, name) in signers {
              if !signer_pubkeys.contains_key(&name) {
                let receiver_pub_key = &mut self.signer_name.to_string().to_uppercase();
                receiver_pub_key.push_str("_PUB");

                let msg = &env::var(receiver_pub_key).unwrap().to_string();

                let message = NetworkMessage {
                  message_type: NetworkMessageType::CoordinatorPubkey,
                  data: msg.as_bytes().to_vec(),
                  receiver_p2p_address: Some(signer_p2p_address.to_string()),
                  sender_p2p_address: swarm.behaviour_mut().signer_p2p_address.to_owned(),
                };
                info!("Sending pubkey to new signer: {} from: {}", &name, &self.signer_name);
                send_message(&message, &mut swarm, &topic);
              }
            }
          }

        }
        event = swarm.select_next_some() => {
                //println!("Swarm event: {:?}", &event);
                match event {
                  libp2p::swarm::SwarmEvent::Behaviour(_) => {
                    info!("Behavior Event");
                  }
                  libp2p::swarm::SwarmEvent::ConnectionEstablished { peer_id, endpoint, num_established, concurrent_dial_errors } => {
                    info!("Connection Established");
                    swarm.behaviour_mut().floodsub.add_node_to_partial_view(peer_id);
                  },
                  libp2p::swarm::SwarmEvent::ConnectionClosed { peer_id, endpoint, num_established, cause } => {
                    info!("Connection Closed");
                    swarm.behaviour_mut().floodsub.remove_node_from_partial_view(&peer_id);
                  }
                  libp2p::swarm::SwarmEvent::IncomingConnection { local_addr, send_back_addr } => {
                    info!("Incoming Connection");
                  }
                  libp2p::swarm::SwarmEvent::IncomingConnectionError { local_addr, send_back_addr, error } => {
                    info!("Incoming Error");
                  }
                  libp2p::swarm::SwarmEvent::OutgoingConnectionError { peer_id, error } => {
                    info!("Outgoing Connection Error");
                  }
                  libp2p::swarm::SwarmEvent::BannedPeer { peer_id, endpoint } => {
                    info!("Banned Peer");
                  }
                  libp2p::swarm::SwarmEvent::NewListenAddr { listener_id, address } => {
                    info!("New Listen Addr");
                  }
                  libp2p::swarm::SwarmEvent::ExpiredListenAddr { listener_id, address } => {
                    info!("Expired Listen Addr");
                  }
                  libp2p::swarm::SwarmEvent::ListenerClosed { listener_id, addresses, reason } => {
                    info!("Listener Closed");
                  }
                  libp2p::swarm::SwarmEvent::ListenerError { listener_id, error } => {
                    info!("Listener Error");
                  },
                  libp2p::swarm::SwarmEvent::Dialing(_) => {
                    info!("Dialing");
                  }
                }
        },
        response = response_rcv.recv() => {
            if let Some(message) = response {
                send_message(&message, &mut swarm, &topic);
            }
        },
        event = ctrl_c() => {
            if let Err(e) = event {
                info!("Failed to register interrupt handler {}", e);
            }
            break;
        }
      }
    }

    io::stdin().read_line(&mut String::new()).unwrap();
  }

  fn stop(self) {
    info!("Stopping Network Process");
  }
}

async fn network_tick() {
  tokio::time::sleep(Duration::from_millis(1000)).await;
}

fn send_response(message: NetworkMessage, sender: mpsc::UnboundedSender<NetworkMessage>) {
  tokio::spawn(async move {
    if let Err(e) = sender.send(message) {
      error!("error sending response via channel {}", e);
    }
  });
}

/// Send a message using the swarm
fn send_message(message: &NetworkMessage, swarm: &mut Swarm<NetworkConnection>, topic: &Topic) {
  let bytes = bincode::serialize(message).unwrap();
  swarm.behaviour_mut().floodsub.publish(topic.clone(), bytes);
}

// Generates Private / Public key pair
fn initialize_keys(name: &str) {
  // Checks if coordinator keys are set
  let mut env_priv_key = name.to_string();
  env_priv_key = env_priv_key.to_uppercase();
  env_priv_key.push_str("_PRIV");

  let coord_priv_check = env::var(env_priv_key);
  if coord_priv_check.is_err() {
    //info!("Generating New Keys");
    // Generates new private / public key
    let (private, public) = message_box::key_gen();
    let private_bytes = unsafe { private.inner().to_repr() };

    let mut env_priv_key = name.to_string();
    env_priv_key = env_priv_key.to_uppercase();
    env_priv_key.push_str("_PRIV");

    let mut env_pub_key = name.to_string();
    env_pub_key = env_pub_key.to_uppercase();
    env_pub_key.push_str("_PUB");

    // Sets private / public key to environment variables
    env::set_var(env_priv_key, hex::encode(&private_bytes.as_ref()));
    env::set_var(env_pub_key, hex::encode(&public.to_bytes()));
  }
}

// Build secure message
fn build_secure_msg(sender_name: &str, receiver_pubkey: PublicKey, msg: &str) -> String {
  let mut sender_pub_key = sender_name.to_string();
  sender_pub_key = sender_pub_key.to_uppercase();
  sender_pub_key.push_str("_PUB");

  let pubkey_string = env::var(sender_pub_key).unwrap().to_string();
  let sender_pub = message_box::PublicKey::from_trusted_str(&pubkey_string);

  let mut sender_priv_key = sender_name.to_string();
  sender_priv_key = sender_priv_key.to_uppercase();
  sender_priv_key.push_str("_PRIV");

  let sender_priv =
    message_box::PrivateKey::from_string(env::var(sender_priv_key).unwrap().to_string());

  let mut message_box_pubkey = HashMap::new();
  message_box_pubkey.insert(receiver_pubkey, receiver_pubkey);

  let message_box = MessageBox::new(sender_pub, sender_priv, message_box_pubkey);
  return message_box.encrypt_to_string(&receiver_pubkey, &msg.clone());
}

// Decrypt secure message
fn decrypt_secure_msg(receiver_name: &str, secured_msg: &str, sender_pubkey: PublicKey) -> String {
  let mut receiver_pub_key = receiver_name.to_string();
  receiver_pub_key = receiver_pub_key.to_uppercase();
  receiver_pub_key.push_str("_PUB");

  let pubkey_string = env::var(receiver_pub_key).unwrap().to_string();
  let receiver_pub = message_box::PublicKey::from_trusted_str(&pubkey_string);

  let mut receiver_priv_key = receiver_name.to_string();
  receiver_priv_key = receiver_priv_key.to_uppercase();
  receiver_priv_key.push_str("_PRIV");

  let receiver_priv =
    message_box::PrivateKey::from_string(env::var(receiver_priv_key).unwrap().to_string());

  let mut message_box_pubkey = HashMap::new();
  message_box_pubkey.insert(sender_pubkey, sender_pubkey);

  let message_box = MessageBox::new(receiver_pub, receiver_priv, message_box_pubkey);
  return message_box.decrypt_from_str(&sender_pubkey, &secured_msg.clone()).unwrap();
}

// Initialize consumers to read the processor pubkey & general test messages on partition 0
fn create_processor_consumers(
  kafka_config: &KafkaConfig,
  name: &str,
  coin_hashmap: &HashMap<Coin, bool>,
  tx: Sender<ProcessorChannelMessage>,
) {
  for (coin, value) in coin_hashmap.into_iter() {
    if value == &true {
      let coin_string = &coin.to_string().clone();
      let mut group_id = name.to_lowercase();
      group_id.push_str("_network_");
      group_id.push_str(&coin_string.to_lowercase());
      let mut topic: String = String::from(name);
      topic.push_str("_processor_");
      topic.push_str(&coin.to_string().to_lowercase());

      let consumer: BaseConsumer = ClientConfig::new()
        .set("bootstrap.servers", format!("{}:{}", kafka_config.host, kafka_config.port))
        .set("group.id", group_id)
        .set("auto.offset.reset", kafka_config.offset_reset.to_owned())
        .create()
        .expect("invalid consumer config");

      let mut tpl = rdkafka::topic_partition_list::TopicPartitionList::new();
      tpl.add_partition(&topic, 0);
      consumer.assign(&tpl).unwrap();

      let tx_clone = tx.clone();
      let cloned_name = name.to_owned();
      let cloned_coin = coin.clone().to_string();
      tokio::spawn(async move {
        for msg_result in &consumer {
          let msg = msg_result.unwrap();
          let key: &str = msg.key_view().unwrap().unwrap();
          let msg_type = parse_message_type(&key);
          match msg_type {
            SignatureMessageType::ProcessorPubkeyToCoordinator => {
              let value = msg.payload().unwrap();
              let public_key = str::from_utf8(value).unwrap();
              let processor_pubkey_msg = ProcessorChannelMessage {
                signer: cloned_name.to_string(),
                coin: cloned_coin.to_string(),
                pubkey: public_key.to_string(),
              };
              tx_clone.send(processor_pubkey_msg).unwrap();
            }
            _ => {}
          }
        }
      });
    }
  }
}
