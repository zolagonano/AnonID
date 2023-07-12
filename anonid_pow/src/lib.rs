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
            auth_address: username.to_string(),
        })
    }

    pub fn merge(&self) -> String {
        format!("{}:{}", self.auth_address, self.username)
    }

    pub fn username_length(&self) -> usize {
        self.username.len()
    }
}

