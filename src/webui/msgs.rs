use std::sync::Arc;

use actix_web::{post, web, Responder, Result};
use retroshare_compat::{
    basics::GxsIdHex,
    services::chat::{ChatId, ChatLobbyId},
    webui::{
        chat::{ChatLobbyIdWrapped, ChatLobbyInfo, VisibleChatLobbyRecord},
        XInt64,
    },
};

use crate::{
    gen_webui_param_type, gen_webui_return_type,
    model::{services::chat::ChatCmd, DataCore},
    webui::RetVal,
};

// rsMsgs/getChatLobbyList
// /**
//  * @brief getChatLobbyList get ids of subscribed lobbies
//  * @jsonapi{development}
//  * @param[out] cl_list lobby list
//  */
//  virtual void getChatLobbyList(std::list<ChatLobbyId> &cl_list) = 0;
gen_webui_return_type!(GetChatLobbyList, cl_list, Vec<XInt64<u64>>);
#[post("/getChatLobbyList")]
pub async fn rs_msgs_get_chat_lobby_list(
    state: web::Data<Arc<DataCore>>,
) -> Result<impl Responder> {
    let chat_lobby_list = state
        .get_service_data()
        .chat()
        .lobbies
        .read()
        .await
        .iter()
        .filter_map(|(&id, lobby)| if lobby.joined { Some(id.into()) } else { None })
        .collect();

    Ok(web::Json(GetChatLobbyList {
        retval: true,
        cl_list: chat_lobby_list,
    }))
}

// rsMsgs/getListOfNearbyChatLobbies
// /**
//  * @brief getListOfNearbyChatLobbies get info about all lobbies, subscribed and unsubscribed
//  * @jsonapi{development}
//  * @param[out] public_lobbies list of all visible lobbies
//  */
//  virtual void getListOfNearbyChatLobbies(std::vector<VisibleChatLobbyRecord> &public_lobbies) = 0 ;
gen_webui_return_type!(
    GetListOfNearbyChatLobbies,
    public_lobbies,
    Vec<VisibleChatLobbyRecord>
);
#[post("/getListOfNearbyChatLobbies")]
pub async fn rs_msgs_get_list_of_nearby_chat_lobbies(
    state: web::Data<Arc<DataCore>>,
) -> Result<impl Responder> {
    let public_lobbies = state
        .get_service_data()
        .chat()
        .lobbies
        .read()
        .await
        .iter()
        .map(|(_, lobby)| lobby.into())
        .collect();

    Ok(web::Json(GetListOfNearbyChatLobbies {
        retval: true,
        public_lobbies,
    }))
}

// rsMsgs/getChatLobbyInfo
// /**
//  * @brief getChatLobbyInfo get lobby info of a subscribed chat lobby. Returns true if lobby id is valid.
//  * @jsonapi{development}
//  * @param[in] id id to get infos from
//  * @param[out] info lobby infos
//  * @return true on success
//  */
//  virtual bool getChatLobbyInfo(const ChatLobbyId &id, ChatLobbyInfo &info) = 0 ;
gen_webui_return_type!(GetChatLobbyInfo, info, ChatLobbyInfo);
#[post("/getChatLobbyInfo")]
pub async fn rs_msgs_get_chat_lobby_info(
    state: web::Data<Arc<DataCore>>,
    id: web::Json<ChatLobbyIdWrapped>,
) -> Result<impl Responder> {
    match state
        .get_service_data()
        .chat()
        .lobbies
        .read()
        .await
        .get(&id.0.into())
    {
        Some(info) => Ok(web::Json(GetChatLobbyInfo {
            retval: true,
            info: info.into(),
        })),
        None => Ok(web::Json(GetChatLobbyInfo {
            retval: false,
            info: ChatLobbyInfo::default(),
        })),
    }
}

// rsmsgs/sendChat
// /*!
//  * Send a chat message.
//  * @param destination where to send the chat message
//  * @param msg the message
//  * @see ChatId
//  */
// virtual bool sendChat(ChatId destination, std::string msg) override ;
gen_webui_param_type!(MsgsSendChat, id: ChatId, msg: String);
#[post("/sendChat")]
pub async fn rs_msgs_send_chat(
    state: web::Data<Arc<DataCore>>,
    params: web::Json<MsgsSendChat>,
) -> Result<impl Responder> {
    let id = params.0.id;
    let msg = params.0.msg;

    let lock = state.get_service_data().chat().cmd.read().await;
    match &*lock {
        Some(tx) => _ = tx.send(ChatCmd::SendMessage(id, msg)),
        None => return Ok(web::Json(RetVal { retval: false })),
    }

    Ok(web::Json(RetVal { retval: true }))
}

// rsMsgs/joinVisibleChatLobby
// /**
//  * @brief joinVisibleChatLobby join a lobby that is visible
//  * @jsonapi{development}
//  * @param[in] lobby_id lobby to join to
//  * @param[in] own_id chat id to use
//  * @return true on success
//  */
//  virtual bool joinVisibleChatLobby(const ChatLobbyId &lobby_id, const RsGxsId &own_id) = 0 ;
gen_webui_param_type!(
    JoinVisibleChatLobby,
    lobby_id: ChatLobbyId,
    own_id: GxsIdHex
);
#[post("/joinVisibleChatLobby")]
pub async fn rs_msgs_join_visible_chat_lobby(
    state: web::Data<Arc<DataCore>>,
    params: web::Json<JoinVisibleChatLobby>,
) -> Result<impl Responder> {
    let lobby = params.0.lobby_id;
    let gxs_id = *params.0.own_id;

    let lock = state.get_service_data().chat().cmd.read().await;
    match &*lock {
        Some(tx) => _ = tx.send(ChatCmd::JoinLobby(lobby, gxs_id)),
        None => return Ok(web::Json(RetVal { retval: false })),
    }

    Ok(web::Json(RetVal { retval: true }))
}

// rsMsgs/unsubscribeChatLobby
// /**
//  * @brief unsubscribeChatLobby leave a chat lobby
//  * @jsonapi{development}
//  * @param[in] lobby_id lobby to leave
//  */
//  virtual void unsubscribeChatLobby(const ChatLobbyId &lobby_id) = 0;
gen_webui_param_type!(UnsubscribeChatLobby, lobby_id: ChatLobbyId);
#[post("/unsubscribeChatLobby")]
pub async fn rs_msgs_unsubscribe_chat_lobby(
    state: web::Data<Arc<DataCore>>,
    params: web::Json<UnsubscribeChatLobby>,
) -> Result<impl Responder> {
    let lobby = params.0.lobby_id;

    let lock = state.get_service_data().chat().cmd.read().await;
    match &*lock {
        Some(tx) => _ = tx.send(ChatCmd::LeaveLobby(lobby)),
        None => return Ok(web::Json(RetVal { retval: false })),
    }

    Ok(web::Json(RetVal { retval: true }))
}

pub fn get_entry_points() -> actix_web::Scope {
    web::scope("/rsMsgs")
        .service(rs_msgs_get_chat_lobby_list)
        .service(rs_msgs_get_list_of_nearby_chat_lobbies)
        .service(rs_msgs_get_chat_lobby_info)
        .service(rs_msgs_send_chat)
        .service(rs_msgs_join_visible_chat_lobby)
        .service(rs_msgs_unsubscribe_chat_lobby)
}
