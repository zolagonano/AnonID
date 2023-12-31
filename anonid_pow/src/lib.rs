use sha2::{Digest, Sha256};

/// Contains username and user's public key
#[derive(Clone)]
pub struct UserData {
    username: String,
    auth_address: String,
}

impl UserData {
    /// Initialize a UserData struct with username and user's public key
    pub fn new(username: String, auth_address: String) -> UserData {
        UserData {
            username,
            auth_address,
        }
    }

    /// Initialize a UserData struct from a merged userdata string
    pub fn from_merged(merged_userdata: String) -> Option<UserData> {
        let userdata: Vec<&str> = merged_userdata.split(":").collect();

        let auth_address = userdata.get(0)?;
        let username = userdata.get(1)?;

        Some(UserData {
            username: username.to_string(),
            auth_address: auth_address.to_string(),
        })
    }

    /// Merges the username and public key to a string
    ///
    /// "auth_address:username"
    ///
    pub fn merge(&self) -> String {
        format!("{}:{}", self.auth_address, self.username)
    }

    /// Returns username's length
    pub fn username_length(&self) -> usize {
        self.username.len()
    }
}

/// Contains the PoW algorithm
#[derive(Clone)]
pub enum PoWAlgo {
    Sha256,
}

impl PoWAlgo {
    /// Calculates the Hash based on the algorithm
    pub fn calculate(&self, userdata: &str, nonce: usize) -> String {
        match self {
            PoWAlgo::Sha256 => {
                let mut hasher = Sha256::new();
                hasher.update(userdata.as_bytes());

                hasher.update(format!(":{nonce}").as_bytes());

                let final_hash = hasher.finalize();

                format!("{:x}", final_hash)
            }
        }
    }
}

/// Contains PoW parameters like difficulty, userdata, and PoW algorithm
#[derive(Clone)]
pub struct PoW {
    userdata: UserData,
    difficulty: usize,
    algo: PoWAlgo,
}

impl PoW {
    /// Initializes a PoW struct from userdata, difficulty, and PoW algorthm
    pub fn new(userdata: UserData, difficulty: usize, algo: PoWAlgo) -> PoW {
        PoW {
            userdata,
            difficulty,
            algo,
        }
    }

    /// Adjusts the difficulty based on the username's length
    ///
    /// As the username's length gets shorter the higher the difficulty will get
    pub fn adjust_difficulty(username_length: usize, difficulty: usize) -> usize {
        let half_difficulty = difficulty / 2;

        let divisor = std::cmp::max(1, username_length / half_difficulty);

        difficulty / divisor
    }

    fn calculate_target(adjusted_difficulty: usize) -> String {
        format!("{:x}", usize::pow(2, adjusted_difficulty as u32) - 1)
    }

    /// Calculates the actual PoW and returns the hash and the nonce as the result
    pub fn calculate_pow(&self) -> (String, usize) {
        let userdata = self.userdata.merge();
        let username_length = self.userdata.username_length();

        let adjusted_difficulty = Self::adjust_difficulty(username_length, self.difficulty);

        let target = Self::calculate_target(adjusted_difficulty);

        let mut nonce = 0;
        loop {
            let hash = self.algo.calculate(&userdata, nonce);

            if hash[..target.len()] == target {
                return (hash, nonce);
            } else {
                nonce += 1;
            }
        }
    }

    /// Verify the PoW from userdata, hash, and nonce
    pub fn verify_pow(&self, pow_value: (String, usize)) -> bool {
        let userdata = self.userdata.merge();
        let username_length = self.userdata.username_length();

        let adjusted_difficulty = Self::adjust_difficulty(username_length, self.difficulty);

        let target = Self::calculate_target(adjusted_difficulty);

        let (input_hash, nonce) = pow_value;

        let computed_hash = self.algo.calculate(&userdata, nonce);

        if computed_hash[..target.len()] == target && computed_hash == input_hash {
            true
        } else {
            false
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{PoW, PoWAlgo, UserData};

    #[test]
    fn test_userdata_merge() {
        let userdata = UserData::new(
            "zeronet_user".to_string(),
            "1FBbx487PoajzgnA4yY6TnoLFhQQteT8UX".to_string(),
        );

        assert_eq!(
            "1FBbx487PoajzgnA4yY6TnoLFhQQteT8UX:zeronet_user",
            userdata.merge()
        );
    }

    #[test]
    fn test_userdata_from_merge() {
        let correct_merged_userdata = "1FBbx487PoajzgnA4yY6TnoLFhQQteT8UX:zeronet_user".to_string();
        let incorrect_merged_userdata = "1FBbx487PoajzgnA4yY6TnoLFhQQteT8UXzeronetuser".to_string();

        assert!(UserData::from_merged(correct_merged_userdata).is_some());
        assert!(UserData::from_merged(incorrect_merged_userdata).is_none());
    }

    #[test]
    fn test_pow_algo() {
        let userdata = "1FBbx487PoajzgnA4yY6TnoLFhQQteT8UX:zeronet_user";
        let nonce = 666;

        let hash = "0729afa04e84848b8535f35df9dab0bad39b1e4c56a2d82443e2ecd89aca1483";

        let pow_algo = PoWAlgo::Sha256;
        let computed_hash = pow_algo.calculate(userdata, nonce);

        assert_eq!(hash, computed_hash);
    }

    #[test]
    fn test_pow_adjust_difficulty() {
        let difficulty = 6;

        assert_eq!(6, PoW::adjust_difficulty(2, difficulty));
        assert_eq!(3, PoW::adjust_difficulty(7, difficulty));
        assert_eq!(2, PoW::adjust_difficulty(10, difficulty));
        assert_eq!(1, PoW::adjust_difficulty(18, difficulty));
    }

    #[test]
    fn test_pow_calculate() {
        let difficulty = 24;

        let userdata =
            UserData::from_merged("1FBbx487PoajzgnA4yY6TnoLFhQQteT8UX:zeronet_user".to_string())
                .unwrap();
        let pow = PoW::new(userdata, difficulty, PoWAlgo::Sha256);

        let expected_result = (
            "ffffff419e9de8f5a3b958da92eb19ed8b6cc6da591de7fec0a2e7250c804047".to_string(),
            6589658_usize,
        );

        assert_eq!(expected_result, pow.calculate_pow());
    }

    #[test]
    fn test_pow_verify() {
        let difficulty = 24;

        let userdata =
            UserData::from_merged("1FBbx487PoajzgnA4yY6TnoLFhQQteT8UX:zeronet_user".to_string())
                .unwrap();
        let pow = PoW::new(userdata, difficulty, PoWAlgo::Sha256);

        let computed_pow = (
            "ffffff419e9de8f5a3b958da92eb19ed8b6cc6da591de7fec0a2e7250c804047".to_string(),
            6589658_usize,
        );

        assert!(pow.verify_pow(computed_pow));
    }
}
