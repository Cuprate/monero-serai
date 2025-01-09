use core::{
  pin::Pin,
  task::{Poll, Context},
  future::Future,
};

pub use async_channel::{SendError, RecvError};

/// The sender for a oneshot channel.
pub struct Sender<T: Send>(async_channel::Sender<T>);
impl<T: Send> Sender<T> {
  /// Send a value down the channel.
  ///
  /// Returns an error if the channel's receiver was dropped.
  pub fn send(self, msg: T) -> Result<(), SendError<T>> {
    self.0.send_blocking(msg)
  }
}

/// The receiver for a oneshot channel.
pub struct Receiver<T: Send>(async_channel::Receiver<T>);
impl<T: Send> Future for Receiver<T> {
  type Output = Result<T, RecvError>;
  fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
    let recv = self.0.recv();
    futures_lite::pin!(recv);
    recv.poll(cx)
  }
}

/// Create a new oneshot channel.
pub fn channel<T: Send>() -> (Sender<T>, Receiver<T>) {
  let (send, recv) = async_channel::bounded(1);
  (Sender(send), Receiver(recv))
}
