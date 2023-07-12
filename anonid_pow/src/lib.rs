use sha2::{Digest, Sha256};

pub struct UserData {
    username: String,
    auth_address: String,
}

impl UserData {
    pub fn new(username: String, auth_address: String) -> UserData {
        UserData {
            username,
            auth_address,
        }
    }

    pub fn from_merged(merged_userdata: String) -> Option<UserData> {
        let userdata: Vec<&str> = merged_userdata.split(":").collect();

        let auth_address = userdata.get(0)?;
        let username = userdata.get(1)?;

        Some(UserData {
            username: username.to_string(),
            auth_address: auth_address.to_string(),
        })
    }

    pub fn merge(&self) -> String {
        format!("{}:{}", self.auth_address, self.username)
    }

    pub fn username_length(&self) -> usize {
        self.username.len()
    }
}

pub enum PoWAlgo {
    Sha256,
}

impl PoWAlgo {
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

pub struct PoW {
    userdata: UserData,
    difficulty: usize,
    algo: PoWAlgo,
}

impl PoW {
    pub fn new(userdata: UserData, difficulty: usize, algo: PoWAlgo) -> PoW {
        PoW {
            userdata,
            difficulty,
            algo,
        }
    }

    pub fn adjust_difficulty(username_length: usize, difficulty: usize) -> usize {
        let half_difficulty = difficulty / 2;

        let divisor = std::cmp::max(1, username_length / half_difficulty);

        difficulty / divisor
    }

    pub fn calculate_pow(&self) -> (String, usize) {
        let userdata = self.userdata.merge();
        let username_length = self.userdata.username_length();

        let adjusted_difficulty = Self::adjust_difficulty(username_length, self.difficulty);

        let target = "0".repeat(adjusted_difficulty);

        let mut nonce = 0;
        loop {
            let hash = self.algo.calculate(&userdata, nonce);

            if hash[..adjusted_difficulty] == target {
                return (hash, nonce);
            } else {
                nonce += 1;
            }
        }
    }

    pub fn verify_pow(&self, pow_value: (String, usize)) -> bool {
        let userdata = self.userdata.merge();
        let username_length = self.userdata.username_length();

        let adjusted_difficulty = Self::adjust_difficulty(username_length, self.difficulty);

        let target = "0".repeat(adjusted_difficulty);

        let (input_hash, nonce) = pow_value;

        let computed_hash = self.algo.calculate(&userdata, nonce);

        if computed_hash[..adjusted_difficulty] == target && computed_hash == input_hash {
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
        let difficulty = 10;

        let userdata =
            UserData::from_merged("1FBbx487PoajzgnA4yY6TnoLFhQQteT8UX:zeronet_user".to_string())
                .unwrap();
        let pow = PoW::new(userdata, difficulty, PoWAlgo::Sha256);

        let expected_result = (
            "00000d311bf66540c9a555f704c27df88e0d5172155771e69d3c7849f2eb07f9".to_string(),
            1276692_usize,
        );

        assert_eq!(expected_result, pow.calculate_pow());
    }

    #[test]
    fn test_pow_verify() {
        let difficulty = 10;

        let userdata =
            UserData::from_merged("1FBbx487PoajzgnA4yY6TnoLFhQQteT8UX:zeronet_user".to_string())
                .unwrap();
        let pow = PoW::new(userdata, difficulty, PoWAlgo::Sha256);

        let computed_pow = (
            "00000d311bf66540c9a555f704c27df88e0d5172155771e69d3c7849f2eb07f9".to_string(),
            1276692_usize,
        );

        assert!(pow.verify_pow(computed_pow));
    }
}
