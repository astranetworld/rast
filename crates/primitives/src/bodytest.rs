use k256::PublicKey;

use crate::TransactionSigned;
pub struct Body{
    pub txs:Vec<TransactionSigned>,
    pub verifiers:Vec<Verify>,
    pub rewards:Vec<Reward>,
}
pub struct Verify{
    pub address:Address,
    pub public_key:PublicKey,
}
const ADDRESS_LENGTH: usize = 20; 
type Address = [u8; ADDRESS_LENGTH];