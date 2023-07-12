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
}
