const DEFAULT_ACCOUNT_ADDRESS_TYPE : AccountAddressType = AccountAddressType::P2PKH;

/// Address type an account is using
#[derive(Copy, Clone, Hash, Eq, PartialEq, Debug)]
pub enum AccountAddressType {
    /// legacy pay to public key hash (BIP44)
    P2PKH,
    /// transitional segwit pay to public key hash in legacy format (BIP49)
    P2SHWPKH,
    /// native segwit pay to public key hash in bech format (BIP84)
    P2WPKH,
    /// native segwit pay to script
    /// do not use 44, 49 or 84 for this parameter, to avoid confusion with above types
    /// Only supports scripts that can be spent with following witness:
    /// <signature> <scriptCode>
    P2WSH(u32),
}

impl AccountAddressType {
    pub fn as_u32(&self) -> u32 {
        match self {
            AccountAddressType::P2PKH => 44,
            AccountAddressType::P2SHWPKH => 49,
            AccountAddressType::P2WPKH => 84,
            AccountAddressType::P2WSH(n) => *n,
        }
    }

    pub fn from_u32(n: u32) -> AccountAddressType {
        match n {
            44 => AccountAddressType::P2PKH,
            49 => AccountAddressType::P2SHWPKH,
            84 => AccountAddressType::P2WPKH,
            n => AccountAddressType::P2WSH(n),
        }
    }
}

impl Default for AccountAddressType {
    fn default() -> Self {
        DEFAULT_ACCOUNT_ADDRESS_TYPE
    }
}
