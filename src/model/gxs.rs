use retroshare_compat::{
    gxs::{GxsGrpMetaData, GxsMsgMetaData},
    sqlite::DbConnection,
};

#[derive(Debug)]
pub enum GxsType {
    Forum,
    Id,
}

#[allow(dead_code)]
#[derive(Debug)]
pub struct Gxs {
    ty: GxsType,
    db: DbConnection,
}

impl Gxs {
    pub fn new(ty: GxsType, db: DbConnection) -> Self {
        Gxs { ty, db }
    }

    pub fn get_meta(&self) -> Vec<GxsGrpMetaData> {
        self.db.get_grp_meta().unwrap()
    }

    pub fn get_msg(&self) -> Vec<GxsMsgMetaData> {
        self.db.get_grp_msg().unwrap()
    }
}
