use std::{thread, collections::HashMap};
use std::{env, str};
use rdkafka::{
  producer::{BaseRecord, ProducerContext, ThreadedProducer},
  consumer::{BaseConsumer, Consumer, ConsumerContext, Rebalance},
  ClientConfig, ClientContext, Message, Offset,
};
use message_box::MessageBox;
use std::time::Duration;
use rdkafka::message::BorrowedMessage;

use serde::{Deserialize};
use crate::ProcessorConfig;
use crate::core::ChainConfig;

#[derive(Clone, Debug, Deserialize)]
pub struct SignatureProcess {
  chain_config: ChainConfig,
}

impl SignatureProcess {
  pub fn new(config: ProcessorConfig) -> Self {
    println!("New Signature Process");
    let chain_config = config.get_chain();
    Self { chain_config: chain_config }
  }

  pub fn run(self) {
    println!("Starting Signature Process");

    // Create Hashmap based on coins
    let coin_hashmap = create_coin_hashmap(&self.chain_config);

    // Create/Start Coordinator Pubkey Consumers
    start_pubkey_consumer();

    // Create Pubkey Producer & Send PubKey
    start_pubkey_producer(&coin_hashmap);

    // Wait to receive Coordinator Pubkey
    process_received_pubkey();

    // Create/Start Public Consumer
    start_public_consumer(&coin_hashmap);

    // Create/Start Private Consumer
    start_private_consumer(&coin_hashmap);

    // Create/Start Public/Private Producer
    start_pub_priv_producer(&coin_hashmap);
  }

  fn stop(self) {
    println!("Stopping Signature Process");
  }
}

// Create/Start Pubkey Consumers
fn start_pubkey_consumer(){
  let consumer: BaseConsumer<ConsumerCallbackLogger> = ClientConfig::new()
    .set("bootstrap.servers", "localhost:9094")
    .set("group.id", "serai")
    .create_with_context(ConsumerCallbackLogger {})
    .expect("invalid consumer config");

  consumer
    .subscribe(&["Coord_Public_Key"])
    .expect("public_key_topic subscribe failed");

  thread::spawn(move || {
    for msg_result in &consumer {
      let msg = msg_result.unwrap();
      let key: &str = msg.key_view().unwrap().unwrap();
      let value = msg.payload().unwrap();
      let public_key = str::from_utf8(value).unwrap();
      println!("Received {} Public Key: {}", &key, &public_key);
      env::set_var("COORD_PUB", public_key);
    }
  });
}

// Create/Start Public Consumer
fn start_public_consumer(coin_hashmap: &HashMap<String, bool> ) {
  let hashmap_clone = coin_hashmap.clone();

  // Loop through each coin & if active, create pubkey consumer
  for (key, value) in hashmap_clone.into_iter() {
    if value == true {
      let mut group_id = String::from(&key);
      group_id.push_str("_public");
      let mut topic = String::from(&key).to_uppercase();
      topic.push_str("_Topic");
      initialize_consumer(&group_id, &topic, None, None, "public");
    }
  }
}

// Create/Start Private Consumer
fn start_private_consumer(coin_hashmap: &HashMap<String, bool> ) {
  let hashmap_clone = coin_hashmap.clone();

  // Loop through each coin & if active, create pubkey consumer
  for (key, value) in hashmap_clone.into_iter() {
    if value == true {
      let mut group_id = String::from(&key);
      group_id.push_str("_private");
      let mut topic = String::from(&key).to_uppercase();
      topic.push_str("_Topic");
      let mut env_key = String::from(&key).to_uppercase();
      env_key.push_str("_PRIV");
      initialize_consumer(&group_id, &topic, Some(env_key.to_string()), Some(&key), "private");
    }
  }
}

// Will Create a Consumer based on Pubkey, Public, or Private
// Pubkey will listen for Processor Pubkey's
// Public will listen for Processor Public Messages
// Private will listen for Processor Private Messages
fn initialize_consumer(group_id: &str, topic: &str, env_key: Option<String>, coin: Option<&String>, consumer_type: &str) {
  let consumer: BaseConsumer<ConsumerCallbackLogger> = ClientConfig::new()
    .set("bootstrap.servers", "localhost:9094")
    .set("group.id", group_id)
    .create_with_context(ConsumerCallbackLogger {})
    .expect("invalid consumer config");

    let mut env_key_ref: String = "".to_string();
    match env_key {
      Some(p) => {
        env_key_ref = String::from(p);
      },
      None => {},
    }

    let mut coin_ref: String = "".to_string();
    match coin {
      Some(p) => {
        coin_ref = String::from(p);
      },
      None => {},
    }

  match consumer_type{
    "pubkey" => {
    consumer.subscribe(&[&topic]).expect("failed to subscribe to topic");
      thread::spawn(move || {
        for msg_result in &consumer {
          let msg = msg_result.unwrap();
          let key: &str = msg.key_view().unwrap().unwrap();
          let value = msg.payload().unwrap();
          let public_key = str::from_utf8(value).unwrap();
          println!("Received {} Public Key: {}", &key, &public_key);
          env::set_var(env_key_ref.clone(), public_key);
        }
      });
    },
    "public" => {
      let mut tpl = rdkafka::topic_partition_list::TopicPartitionList::new();
      tpl.add_partition(&topic, 0);
      consumer.assign(&tpl).unwrap();
    
      thread::spawn(move || {
        for msg_result in &consumer {
            let msg = msg_result.unwrap();
            let key: &str = msg.key_view().unwrap().unwrap();
            if message_box::ids::COORDINATOR == &*key {
              let value = msg.payload().unwrap();
              let pub_msg = str::from_utf8(value).unwrap();
              println!("Received Public Message from {}", &key);
              println!("Public Message: {}", &pub_msg);
            }
          }
        });
      },
      "private" => {
        let mut tpl = rdkafka::topic_partition_list::TopicPartitionList::new();
        tpl.add_partition(&topic, 1);
        consumer.assign(&tpl).unwrap();
      
        thread::spawn(move || {
          for msg_result in &consumer {
            let msg = msg_result.unwrap();
            let key: &str = msg.key_view().unwrap().unwrap();
            if message_box::ids::COORDINATOR != &*key {
                let value = msg.payload().unwrap();
                // Creates Message box used for decryption
                let pubkey =
                  message_box::PublicKey::from_trusted_str(&env::var("COORD_PUB").unwrap().to_string());
      
                let coin_priv =
                  message_box::PrivateKey::from_string(env::var(env_key_ref.to_string()).unwrap().to_string());

                let processor_id = retrieve_message_box_id(&coin_ref);

                let mut message_box_pubkeys = HashMap::new();
                message_box_pubkeys.insert(message_box::ids::COORDINATOR, pubkey);
      
                let message_box = MessageBox::new(processor_id, coin_priv, message_box_pubkeys);
                let encrypted_msg = str::from_utf8(value).unwrap();
      
                // Decrypt message using Message Box
                let encoded_string =
                  message_box.decrypt_from_str(&message_box::ids::COORDINATOR, &encrypted_msg).unwrap();
                let decoded_string = String::from_utf8(encoded_string).unwrap();
                println!("Received Encrypted Message from {}", &key);
                println!("Decrypted Message: {}", &decoded_string);
              }
            }
          });
        },
    _ => {},
  }
}

// Create Pubkey Producer & Send PubKey
fn start_pubkey_producer(coin_hashmap: &HashMap<String, bool>){
  let hashmap_clone = coin_hashmap.clone();
  // Loop through each coin & if active, create pubkey consumer
  for (key, value) in hashmap_clone.into_iter() {
    if value == true {
      let mut topic = String::from(&key).to_uppercase();
      topic.push_str("_Public_Key");
      let mut env_key = String::from(&key).to_uppercase();
      env_key.push_str("_PUB");
      let processor_id = retrieve_message_box_id(&key);
      send_pubkey_from_producer(&topic, env_key.to_string(), processor_id);
    }
  }
}

fn send_pubkey_from_producer(topic: &str, env_key: String, processor: &'static str) {
  let producer: ThreadedProducer<ProduceCallbackLogger> = ClientConfig::new()
    .set("bootstrap.servers", "localhost:9094")
    .create_with_context(ProduceCallbackLogger {})
    .expect("invalid producer config");

  // Load Pubkeys for processor
  let coin_pub = env::var(env_key.to_string());
  let coin_msg = coin_pub.unwrap();

  // Send pubkey to kafka topic
  producer
    .send(BaseRecord::to(&topic).key(&format!("{}", processor)).payload(&coin_msg))
    .expect("failed to send message");
  thread::sleep(Duration::from_secs(1));
}

// Wait to receive all Processer Pubkeys
fn process_received_pubkey(){
  // Runs a loop to check if Coordinator pubkey is found
  let mut coord_key_found = false;
  while !coord_key_found {
    let coord_pub_check = env::var("COORD_PUB");
    if (!coord_pub_check.is_err()) {
      println!("Coord Pubkey Ready");
      coord_key_found = true;
    } else {
      thread::sleep(Duration::from_secs(1));
    }
  }
}

// Create Hashmap based on coins
fn create_coin_hashmap(chain_config: &ChainConfig) -> HashMap<String, bool> {
  // Create Hashmap based on coins
  let j = serde_json::to_string(&chain_config).unwrap();
  let coins: HashMap<String, bool> = serde_json::from_str(&j).unwrap();
  coins
}

// Requests Coin ID from Message Box
fn retrieve_message_box_id(coin:&String) -> &'static str{
  let id = match coin.as_str() {
    "btc" => message_box::ids::BTC_PROCESSOR,
    "eth" => message_box::ids::ETH_PROCESSOR,
    "xmr" => message_box::ids::XMR_PROCESSOR,
    &_ => "",
  };
  id
}

fn start_pub_priv_producer(coin_hashmap: &HashMap<String, bool>) {
  let hashmap_clone = coin_hashmap.clone();

  // Loop through each coin & if active, create pubkey consumer
  for (key, value) in hashmap_clone.into_iter() {
    if value == true {
      let mut topic = String::from(&key).to_uppercase();
      topic.push_str("_Topic");
      let mut env_key = String::from(&key).to_uppercase();
      env_key.push_str("_PRIV");

      let processor_id = retrieve_message_box_id(&key);
      let mut msg: String = "".to_string();
      msg.push_str(&processor_id);
      msg.push_str(" message to Coordinator");

      send_message_from_pub_priv_producer(
        &topic,
        env_key.to_string(),
        &processor_id,
        msg.as_bytes().to_vec()
      );
    }
  }
}

fn send_message_from_pub_priv_producer(topic: &str, env_key: String, processor: &'static str, msg: Vec<u8>) {
  let producer: ThreadedProducer<ProduceCallbackLogger> = ClientConfig::new()
    .set("bootstrap.servers", "localhost:9094")
    .create_with_context(ProduceCallbackLogger {})
    .expect("invalid producer config");

  // Load Coordinator private environment variable
  let coin_priv =
    message_box::PrivateKey::from_string(env::var(env_key.to_string()).unwrap().to_string());

  // Load Pubkeys for processors
  let pubkey =
    message_box::PublicKey::from_trusted_str(&env::var("COORD_PUB").unwrap().to_string());
  let mut message_box_pubkey = HashMap::new();
  message_box_pubkey.insert(message_box::ids::COORDINATOR, pubkey);

  // Create Coordinator Message Box
  let message_box = MessageBox::new(processor, coin_priv, message_box_pubkey);
  let enc = message_box.encrypt_to_string(&message_box::ids::COORDINATOR, &msg.clone());

  // Partition 1 is Private
  producer
    .send(BaseRecord::to(&topic).key(&format!("{}", &processor)).payload(&enc).partition(1))
    .expect("failed to send message");
  thread::sleep(Duration::from_secs(1));

  // Partition 2 is public
  producer
    .send(BaseRecord::to(&topic).key(&format!("{}", &processor)).payload(&msg).partition(0))
    .expect("failed to send message");
  thread::sleep(Duration::from_secs(1));
}

struct ConsumerCallbackLogger;

impl ClientContext for ConsumerCallbackLogger {}

impl ConsumerContext for ConsumerCallbackLogger {
  fn pre_rebalance<'a>(&self, _rebalance: &rdkafka::consumer::Rebalance<'a>) {}

  fn post_rebalance<'a>(&self, rebalance: &rdkafka::consumer::Rebalance<'a>) {
    //println!("post_rebalance callback");

    match rebalance {
      Rebalance::Assign(tpl) => {
        for e in tpl.elements() {
          //println!("rebalanced partition {}", e.partition())
        }
      }
      Rebalance::Revoke(tpl) => {
        //println!("ALL partitions have been REVOKED")
      }
      Rebalance::Error(err_info) => {
        //println!("Post Rebalance error {}", err_info)
      }
    }
  }

  fn commit_callback(
    &self,
    result: rdkafka::error::KafkaResult<()>,
    offsets: &rdkafka::TopicPartitionList,
  ) {
    match result {
      Ok(_) => {
        for e in offsets.elements() {
          match e.offset() {
            //skip Invalid offset
            Offset::Invalid => {}
            _ => {
              //println!("committed offset {:?} in partition {}", e.offset(), e.partition())
            }
          }
        }
      }
      Err(err) => {
        println!("error committing offset - {}", err)
      }
    }
  }
}

struct ProduceCallbackLogger;

impl ClientContext for ProduceCallbackLogger {}

impl ProducerContext for ProduceCallbackLogger {
  type DeliveryOpaque = ();

  fn delivery(
    &self,
    delivery_result: &rdkafka::producer::DeliveryResult<'_>,
    _delivery_opaque: Self::DeliveryOpaque,
  ) {
    let dr = delivery_result.as_ref();
    let msg = dr.unwrap();

    match dr {
      Ok(msg) => {
        let key: &str = msg.key_view().unwrap().unwrap();
        // println!(
        //   "Produced message with key {} in offset {} of partition {}",
        //   key,
        //   msg.offset(),
        //   msg.partition()
        // );
      }
      Err(producer_err) => {
        let key: &str = producer_err.1.key_view().unwrap().unwrap();

        println!("failed to produce message with key {} - {}", key, producer_err.0,)
      }
    }
  }
}