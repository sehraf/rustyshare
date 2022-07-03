use tokio::sync::oneshot;

pub mod chat;
pub mod gxs_id;

#[derive(Debug)]
pub struct AppRequest<IN, OUT> {
    // TODO
    pub ty: IN,
    pub tx: oneshot::Sender<OUT>,
}
