use rand::prelude::*;
use std::collections::HashMap;
use std::fmt;

// Character sets for password generation
const LOWERCASE: &str = "abcdefghijklmnopqrstuvwxyz";
const UPPERCASE: &str = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
const NUMBERS: &str = "0123456789";
const SYMBOLS: &str = "!@#$%^&*()_+-=[]{}|;:,.<>?";
const SAFE_SYMBOLS: &str = "!@#$%^&*-_=+";

// Common passwords and patterns to avoid
const COMMON_PASSWORDS: &[&str] = &[
    "password",
    "123456",
    "password123",
    "admin",
    "qwerty",
    "letmein",
    "welcome",
    "monkey",
    "dragon",
    "master",
    "sunshine",
    "princess",
];

const KEYBOARD_PATTERNS: &[&str] = &["qwerty", "asdf", "zxcv", "123456", "987654", "abcdef"];

#[derive(Debug, Clone, PartialEq)]
pub enum StrengthLevel {
    VeryWeak,
    Weak,
    Fair,
    Good,
    Strong,
    VeryStrong,
}

impl fmt::Display for StrengthLevel {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            StrengthLevel::VeryWeak => write!(f, "Very Weak"),
            StrengthLevel::Weak => write!(f, "Weak"),
            StrengthLevel::Fair => write!(f, "Fair"),
            StrengthLevel::Good => write!(f, "Good"),
            StrengthLevel::Strong => write!(f, "Strong"),
            StrengthLevel::VeryStrong => write!(f, "Very Strong"),
        }
    }
}

#[derive(Debug)]
pub struct PasswordAnalysis {
    pub strength: StrengthLevel,
    pub score: u32,
    pub entropy: f64,
    pub time_to_crack: String,
    pub feedback: Vec<String>,
    pub character_composition: CharacterComposition,
}

#[derive(Debug)]
pub struct CharacterComposition {
    pub length: usize,
    pub has_lowercase: bool,
    pub has_uppercase: bool,
    pub has_numbers: bool,
    pub has_symbols: bool,
    pub unique_chars: usize,
    pub repeated_chars: usize,
}

// Main trait for password policies
pub trait PasswordPolicy {
    fn meets_requirements(&self, password: &str) -> bool;
    fn generate(&self) -> String;
    fn get_requirements(&self) -> String;
    fn analyze_strength(&self, password: &str) -> PasswordAnalysis;
}

// Corporate password policy (common in enterprises)
#[derive(Debug, Clone)]
pub struct CorporatePolicy {
    pub min_length: usize,
    pub max_length: usize,
    pub require_uppercase: bool,
    pub require_lowercase: bool,
    pub require_numbers: bool,
    pub require_symbols: bool,
    pub min_unique_chars: usize,
    pub forbid_common_passwords: bool,
    pub forbid_keyboard_patterns: bool,
}

impl Default for CorporatePolicy {
    fn default() -> Self {
        Self {
            min_length: 12,
            max_length: 128,
            require_uppercase: true,
            require_lowercase: true,
            require_numbers: true,
            require_symbols: true,
            min_unique_chars: 8,
            forbid_common_passwords: true,
            forbid_keyboard_patterns: true,
        }
    }
}

impl PasswordPolicy for CorporatePolicy {
    fn meets_requirements(&self, password: &str) -> bool {
        let composition = self.analyze_composition(password);

        // Check length
        if password.len() < self.min_length || password.len() > self.max_length {
            return false;
        }

        // Check character requirements
        if self.require_uppercase && !composition.has_uppercase {
            return false;
        }
        if self.require_lowercase && !composition.has_lowercase {
            return false;
        }
        if self.require_numbers && !composition.has_numbers {
            return false;
        }
        if self.require_symbols && !composition.has_symbols {
            return false;
        }

        // Check unique characters
        if composition.unique_chars < self.min_unique_chars {
            return false;
        }

        // Check against common passwords
        if self.forbid_common_passwords {
            let password_lower = password.to_lowercase();
            for common in COMMON_PASSWORDS {
                if password_lower.contains(common) {
                    return false;
                }
            }
        }

        // Check for keyboard patterns
        if self.forbid_keyboard_patterns {
            let password_lower = password.to_lowercase();
            for pattern in KEYBOARD_PATTERNS {
                if password_lower.contains(pattern) {
                    return false;
                }
            }
        }

        true
    }

    fn generate(&self) -> String {
        let mut rng = thread_rng();
        let mut attempts = 0;
        const MAX_ATTEMPTS: u32 = 1000;

        while attempts < MAX_ATTEMPTS {
            let password = self.generate_candidate(&mut rng);
            if self.meets_requirements(&password) {
                return password;
            }
            attempts += 1;
        }

        // Fallback: generate a guaranteed compliant password
        self.generate_guaranteed_compliant(&mut rng)
    }

    fn get_requirements(&self) -> String {
        let mut requirements = Vec::new();

        requirements.push(format!(
            "Length: {}-{} characters",
            self.min_length, self.max_length
        ));

        if self.require_uppercase {
            requirements.push("At least one uppercase letter".to_string());
        }
        if self.require_lowercase {
            requirements.push("At least one lowercase letter".to_string());
        }
        if self.require_numbers {
            requirements.push("At least one number".to_string());
        }
        if self.require_symbols {
            requirements.push("At least one symbol".to_string());
        }

        requirements.push(format!(
            "At least {} unique characters",
            self.min_unique_chars
        ));

        if self.forbid_common_passwords {
            requirements.push("No common passwords or words".to_string());
        }
        if self.forbid_keyboard_patterns {
            requirements.push("No keyboard patterns".to_string());
        }

        requirements.join("\n• ")
    }

    fn analyze_strength(&self, password: &str) -> PasswordAnalysis {
        let composition = self.analyze_composition(password);
        let mut score = 0u32;
        let mut feedback = Vec::new();

        // Length scoring
        match password.len() {
            0..=7 => {
                feedback.push("Password is too short".to_string());
            }
            8..=11 => {
                score += 10;
                feedback.push("Consider using a longer password".to_string());
            }
            12..=15 => score += 20,
            16..=20 => score += 25,
            _ => score += 30,
        }

        // Character variety scoring
        let mut char_types_used = 0;
        if composition.has_lowercase {
            score += 5;
            char_types_used += 1;
        } else {
            feedback.push("Add lowercase letters".to_string());
        }

        if composition.has_uppercase {
            score += 5;
            char_types_used += 1;
        } else {
            feedback.push("Add uppercase letters".to_string());
        }

        if composition.has_numbers {
            score += 5;
            char_types_used += 1;
        } else {
            feedback.push("Add numbers".to_string());
        }

        if composition.has_symbols {
            score += 10;
            char_types_used += 1;
        } else {
            feedback.push("Add symbols for better security".to_string());
        }

        // Bonus for using all character types
        if char_types_used == 4 {
            score += 10;
        }

        // Unique characters bonus
        let uniqueness_ratio = composition.unique_chars as f64 / password.len() as f64;
        score += (uniqueness_ratio * 20.0) as u32;

        if composition.repeated_chars > password.len() / 3 {
            score = score.saturating_sub(10);
            feedback.push("Too many repeated characters".to_string());
        }

        // Check for common passwords
        let password_lower = password.to_lowercase();
        let mut has_common_password = false;
        for common in COMMON_PASSWORDS {
            if password_lower.contains(common) {
                score = score.saturating_sub(20);
                feedback.push("Avoid common passwords and words".to_string());
                has_common_password = true;
                break;
            }
        }

        // Check for keyboard patterns
        let mut has_keyboard_pattern = false;
        for pattern in KEYBOARD_PATTERNS {
            if password_lower.contains(pattern) {
                score = score.saturating_sub(15);
                feedback.push("Avoid keyboard patterns".to_string());
                has_keyboard_pattern = true;
                break;
            }
        }

        // Bonus for long passwords without common issues
        if password.len() > 20 && !has_common_password && !has_keyboard_pattern {
            score += 15;
        }
        if password.len() > 30 && !has_common_password && !has_keyboard_pattern {
            score += 10;
        }

        // Calculate entropy
        let charset_size = self.calculate_charset_size(&composition);
        let entropy = (password.len() as f64) * (charset_size as f64).log2();

        // Determine strength level - adjusted thresholds
        let strength = match score {
            0..=25 => StrengthLevel::VeryWeak,
            26..=45 => StrengthLevel::Weak,
            46..=65 => StrengthLevel::Fair,
            66..=80 => StrengthLevel::Good,
            81..=95 => StrengthLevel::Strong,
            _ => StrengthLevel::VeryStrong,
        };

        let time_to_crack = self.estimate_crack_time(entropy);

        if feedback.is_empty() {
            feedback.push("Excellent password!".to_string());
        }

        PasswordAnalysis {
            strength,
            score,
            entropy,
            time_to_crack,
            feedback,
            character_composition: composition,
        }
    }
}

impl CorporatePolicy {
    fn analyze_composition(&self, password: &str) -> CharacterComposition {
        let mut has_lowercase = false;
        let mut has_uppercase = false;
        let mut has_numbers = false;
        let mut has_symbols = false;
        let mut char_counts = HashMap::new();

        for ch in password.chars() {
            *char_counts.entry(ch).or_insert(0) += 1;

            if ch.is_ascii_lowercase() {
                has_lowercase = true;
            } else if ch.is_ascii_uppercase() {
                has_uppercase = true;
            } else if ch.is_ascii_digit() {
                has_numbers = true;
            } else {
                has_symbols = true;
            }
        }

        let unique_chars = char_counts.len();
        let repeated_chars = char_counts.values().filter(|&&count| count > 1).count();

        CharacterComposition {
            length: password.len(),
            has_lowercase,
            has_uppercase,
            has_numbers,
            has_symbols,
            unique_chars,
            repeated_chars,
        }
    }

    fn generate_candidate(&self, rng: &mut ThreadRng) -> String {
        let mut charset = String::new();

        if self.require_lowercase {
            charset.push_str(LOWERCASE);
        }
        if self.require_uppercase {
            charset.push_str(UPPERCASE);
        }
        if self.require_numbers {
            charset.push_str(NUMBERS);
        }
        if self.require_symbols {
            charset.push_str(SAFE_SYMBOLS);
        }

        if charset.is_empty() {
            charset = format!("{}{}{}{}", LOWERCASE, UPPERCASE, NUMBERS, SAFE_SYMBOLS);
        }

        let charset_chars: Vec<char> = charset.chars().collect();
        let length = rng.gen_range(self.min_length..=self.max_length.min(32));

        (0..length)
            .map(|_| charset_chars[rng.gen_range(0..charset_chars.len())])
            .collect()
    }

    fn generate_guaranteed_compliant(&self, rng: &mut ThreadRng) -> String {
        let mut password = String::new();

        // Ensure at least one of each required character type
        if self.require_lowercase {
            password.push(LOWERCASE.chars().choose(rng).unwrap());
        }
        if self.require_uppercase {
            password.push(UPPERCASE.chars().choose(rng).unwrap());
        }
        if self.require_numbers {
            password.push(NUMBERS.chars().choose(rng).unwrap());
        }
        if self.require_symbols {
            password.push(SAFE_SYMBOLS.chars().choose(rng).unwrap());
        }

        // Fill the rest with random characters
        let all_chars = format!("{}{}{}{}", LOWERCASE, UPPERCASE, NUMBERS, SAFE_SYMBOLS);
        let all_chars: Vec<char> = all_chars.chars().collect();

        while password.len() < self.min_length {
            password.push(all_chars[rng.gen_range(0..all_chars.len())]);
        }

        // Shuffle the password to avoid predictable patterns
        let mut chars: Vec<char> = password.chars().collect();
        chars.shuffle(rng);
        chars.into_iter().collect()
    }

    fn calculate_charset_size(&self, composition: &CharacterComposition) -> usize {
        let mut size = 0;

        if composition.has_lowercase {
            size += 26;
        }
        if composition.has_uppercase {
            size += 26;
        }
        if composition.has_numbers {
            size += 10;
        }
        if composition.has_symbols {
            size += 32; // Approximate number of common symbols
        }

        size.max(1)
    }

    fn estimate_crack_time(&self, entropy: f64) -> String {
        // Assume 1 billion guesses per second (modern hardware)
        let guesses_per_second = 1_000_000_000.0;
        let total_combinations = 2_f64.powf(entropy);
        let seconds_to_crack = total_combinations / (2.0 * guesses_per_second);

        if seconds_to_crack < 1.0 {
            "Instantly".to_string()
        } else if seconds_to_crack < 60.0 {
            format!("{:.0} seconds", seconds_to_crack)
        } else if seconds_to_crack < 3600.0 {
            format!("{:.0} minutes", seconds_to_crack / 60.0)
        } else if seconds_to_crack < 86400.0 {
            format!("{:.0} hours", seconds_to_crack / 3600.0)
        } else if seconds_to_crack < 31536000.0 {
            format!("{:.0} days", seconds_to_crack / 86400.0)
        } else if seconds_to_crack < 31536000000.0 {
            format!("{:.0} years", seconds_to_crack / 31536000.0)
        } else {
            "Centuries".to_string()
        }
    }
}

// High-security policy for sensitive systems
#[derive(Debug, Clone)]
pub struct HighSecurityPolicy {
    pub min_length: usize,
    pub require_all_char_types: bool,
    pub min_entropy: f64,
}

impl Default for HighSecurityPolicy {
    fn default() -> Self {
        Self {
            min_length: 16,
            require_all_char_types: true,
            min_entropy: 60.0,
        }
    }
}

impl PasswordPolicy for HighSecurityPolicy {
    fn meets_requirements(&self, password: &str) -> bool {
        if password.len() < self.min_length {
            return false;
        }

        if self.require_all_char_types {
            let has_lower = password.chars().any(|c| c.is_ascii_lowercase());
            let has_upper = password.chars().any(|c| c.is_ascii_uppercase());
            let has_digit = password.chars().any(|c| c.is_ascii_digit());
            let has_symbol = password.chars().any(|c| !c.is_ascii_alphanumeric());

            if !(has_lower && has_upper && has_digit && has_symbol) {
                return false;
            }
        }

        // Calculate entropy
        let charset_size = self.estimate_charset_size(password);
        let entropy = (password.len() as f64) * (charset_size as f64).log2();

        entropy >= self.min_entropy
    }

    fn generate(&self) -> String {
        let mut rng = thread_rng();

        // Generate a high-entropy password
        loop {
            let mut password = String::new();

            // Ensure all character types
            password.push(LOWERCASE.chars().choose(&mut rng).unwrap());
            password.push(UPPERCASE.chars().choose(&mut rng).unwrap());
            password.push(NUMBERS.chars().choose(&mut rng).unwrap());
            password.push(SYMBOLS.chars().choose(&mut rng).unwrap());

            // Fill with random characters
            let all_chars = format!("{}{}{}{}", LOWERCASE, UPPERCASE, NUMBERS, SYMBOLS);
            let all_chars: Vec<char> = all_chars.chars().collect();

            while password.len() < self.min_length {
                password.push(all_chars[rng.gen_range(0..all_chars.len())]);
            }

            // Shuffle
            let mut chars: Vec<char> = password.chars().collect();
            chars.shuffle(&mut rng);
            let password: String = chars.into_iter().collect();

            if self.meets_requirements(&password) {
                return password;
            }
        }
    }

    fn get_requirements(&self) -> String {
        format!(
            "• Minimum length: {} characters\n\
             • Must contain uppercase, lowercase, numbers, and symbols\n\
             • Minimum entropy: {:.1} bits",
            self.min_length, self.min_entropy
        )
    }

    fn analyze_strength(&self, password: &str) -> PasswordAnalysis {
        // Reuse corporate policy analysis but with stricter scoring
        let corporate = CorporatePolicy::default();
        let mut analysis = corporate.analyze_strength(password);

        // Adjust score based on high-security requirements
        if password.len() >= self.min_length {
            analysis.score += 10;
        } else {
            analysis.score = analysis.score.saturating_sub(20);
            analysis
                .feedback
                .push("Password too short for high security".to_string());
        }

        if analysis.entropy >= self.min_entropy {
            analysis.score += 15;
        } else {
            analysis.score = analysis.score.saturating_sub(15);
            analysis
                .feedback
                .push("Insufficient entropy for high security".to_string());
        }

        // Recalculate strength with adjusted score
        analysis.strength = match analysis.score {
            0..=30 => StrengthLevel::VeryWeak,
            31..=50 => StrengthLevel::Weak,
            51..=70 => StrengthLevel::Fair,
            71..=85 => StrengthLevel::Good,
            86..=95 => StrengthLevel::Strong,
            _ => StrengthLevel::VeryStrong,
        };

        analysis
    }
}

impl HighSecurityPolicy {
    fn estimate_charset_size(&self, password: &str) -> usize {
        let mut size = 0;

        if password.chars().any(|c| c.is_ascii_lowercase()) {
            size += 26;
        }
        if password.chars().any(|c| c.is_ascii_uppercase()) {
            size += 26;
        }
        if password.chars().any(|c| c.is_ascii_digit()) {
            size += 10;
        }
        if password.chars().any(|c| !c.is_ascii_alphanumeric()) {
            size += 32;
        }

        size.max(1)
    }
}

// FIXED: Using enum instead of trait objects to avoid object safety issues
#[derive(Debug, Clone)]
pub enum PolicyType {
    Corporate(CorporatePolicy),
    HighSecurity(HighSecurityPolicy),
}

impl PolicyType {
    pub fn meets_requirements(&self, password: &str) -> bool {
        match self {
            PolicyType::Corporate(policy) => policy.meets_requirements(password),
            PolicyType::HighSecurity(policy) => policy.meets_requirements(password),
        }
    }

    pub fn generate(&self) -> String {
        match self {
            PolicyType::Corporate(policy) => policy.generate(),
            PolicyType::HighSecurity(policy) => policy.generate(),
        }
    }

    pub fn get_requirements(&self) -> String {
        match self {
            PolicyType::Corporate(policy) => policy.get_requirements(),
            PolicyType::HighSecurity(policy) => policy.get_requirements(),
        }
    }

    pub fn analyze_strength(&self, password: &str) -> PasswordAnalysis {
        match self {
            PolicyType::Corporate(policy) => policy.analyze_strength(password),
            PolicyType::HighSecurity(policy) => policy.analyze_strength(password),
        }
    }
}

// FIXED: Utility struct for batch operations - now using enum instead of trait objects
#[derive(Debug)]
pub struct PasswordManager {
    policies: HashMap<String, PolicyType>,
    default_policy: String,
}

impl PasswordManager {
    pub fn new() -> Self {
        let mut policies = HashMap::new();
        policies.insert(
            "corporate".to_string(),
            PolicyType::Corporate(CorporatePolicy::default()),
        );
        policies.insert(
            "high-security".to_string(),
            PolicyType::HighSecurity(HighSecurityPolicy::default()),
        );

        Self {
            policies,
            default_policy: "corporate".to_string(),
        }
    }

    pub fn add_corporate_policy(&mut self, name: String, policy: CorporatePolicy) {
        self.policies.insert(name, PolicyType::Corporate(policy));
    }

    pub fn add_high_security_policy(&mut self, name: String, policy: HighSecurityPolicy) {
        self.policies.insert(name, PolicyType::HighSecurity(policy));
    }

    pub fn generate_batch(&self, count: usize, policy_name: Option<&str>) -> Vec<String> {
        let policy_name = policy_name.unwrap_or(&self.default_policy);
        if let Some(policy) = self.policies.get(policy_name) {
            (0..count).map(|_| policy.generate()).collect()
        } else {
            eprintln!(
                "Warning: Policy '{}' not found, returning empty vector",
                policy_name
            );
            vec![]
        }
    }

    pub fn analyze_batch(
        &self,
        passwords: &[String],
        policy_name: Option<&str>,
    ) -> Vec<PasswordAnalysis> {
        let policy_name = policy_name.unwrap_or(&self.default_policy);
        if let Some(policy) = self.policies.get(policy_name) {
            passwords
                .iter()
                .map(|pwd| policy.analyze_strength(pwd))
                .collect()
        } else {
            eprintln!(
                "Warning: Policy '{}' not found, returning empty vector",
                policy_name
            );
            vec![]
        }
    }

    pub fn list_policies(&self) -> Vec<&String> {
        self.policies.keys().collect()
    }

    pub fn set_default_policy(&mut self, policy_name: String) -> Result<(), String> {
        if self.policies.contains_key(&policy_name) {
            self.default_policy = policy_name;
            Ok(())
        } else {
            Err(format!("Policy '{}' not found", policy_name))
        }
    }
}

// Example usage and tests
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_corporate_policy_generation() {
        let policy = CorporatePolicy::default();
        let password = policy.generate();

        assert!(policy.meets_requirements(&password));
        assert!(password.len() >= policy.min_length);
    }

    #[test]
    fn test_password_strength_analysis() {
        let policy = CorporatePolicy::default();

        let weak_password = "password123";
        let analysis = policy.analyze_strength(weak_password);
        println!(
            "Weak password '{}': {} (score: {})",
            weak_password, analysis.strength, analysis.score
        );
        assert!(matches!(
            analysis.strength,
            StrengthLevel::VeryWeak | StrengthLevel::Weak
        ));

        let strong_password = "X7$kL9@nQ2&mP5!w";
        let analysis = policy.analyze_strength(strong_password);
        println!(
            "Strong password '{}': {} (score: {})",
            strong_password, analysis.strength, analysis.score
        );
        println!("Feedback: {:?}", analysis.feedback);

        // The password should be at least Fair or better
        assert!(matches!(
            analysis.strength,
            StrengthLevel::Fair
                | StrengthLevel::Good
                | StrengthLevel::Strong
                | StrengthLevel::VeryStrong
        ));

        // Test with a guaranteed very strong password that should score high
        let very_strong_password = "Tr0ub4dor&3MyVeryL0ngP@ssw0rd!2024#Secure";
        let analysis = policy.analyze_strength(very_strong_password);
        println!(
            "Very strong password '{}': {} (score: {})",
            very_strong_password, analysis.strength, analysis.score
        );
        assert!(matches!(
            analysis.strength,
            StrengthLevel::Strong | StrengthLevel::VeryStrong
        ));
    }

    #[test]
    fn test_high_security_policy() {
        let policy = HighSecurityPolicy::default();
        let password = policy.generate();

        assert!(policy.meets_requirements(&password));
        assert!(password.len() >= 16);
    }

    #[test]
    fn test_password_manager() {
        let manager = PasswordManager::new();
        let passwords = manager.generate_batch(5, None);

        assert_eq!(passwords.len(), 5);

        let analyses = manager.analyze_batch(&passwords, None);
        assert_eq!(analyses.len(), 5);
    }

    #[test]
    fn test_policy_management() {
        let mut manager = PasswordManager::new();

        // Test adding custom policy
        let custom_corporate = CorporatePolicy {
            min_length: 8,
            max_length: 20,
            require_uppercase: true,
            require_lowercase: true,
            require_numbers: false,
            require_symbols: false,
            min_unique_chars: 5,
            forbid_common_passwords: true,
            forbid_keyboard_patterns: false,
        };

        manager.add_corporate_policy("custom".to_string(), custom_corporate);

        let policies = manager.list_policies();
        assert!(policies.iter().any(|&name| name == "custom"));
    }
}

mod cli;

fn main() {
    // Check if any CLI arguments are provided
    let args: Vec<String> = std::env::args().collect();

    if args.len() > 1 {
        // Run CLI interface
        cli::run_cli();
    } else {
        // Run demo/example interface
        run_demo();
    }
}

fn run_demo() {
    println!("Password Generator & Strength Analyzer");
    println!("=====================================");
    println!("💡 Tip: Use 'password-tool --help' for CLI usage\n");

    // Create password manager
    let manager = PasswordManager::new();

    // Generate some corporate passwords
    println!("🏢 Corporate Policy Passwords:");
    let corporate_passwords = manager.generate_batch(3, Some("corporate"));
    for (i, password) in corporate_passwords.iter().enumerate() {
        println!("{}. {}", i + 1, password);
    }

    // Generate high-security passwords
    println!("\n🔒 High-Security Policy Passwords:");
    let secure_passwords = manager.generate_batch(3, Some("high-security"));
    for (i, password) in secure_passwords.iter().enumerate() {
        println!("{}. {}", i + 1, password);
    }

    // Analyze password strength
    println!("\n📊 Password Strength Analysis:");
    let test_passwords = vec![
        "password123".to_string(),
        "MyP@ssw0rd!2024".to_string(),
        "X7$kL9@nQ2&mP5!wR8#tU3*vY6+".to_string(),
    ];

    let corporate_policy = CorporatePolicy::default();

    for password in &test_passwords {
        let analysis = corporate_policy.analyze_strength(password);
        println!("\n🔑 Password: {}", password);
        println!(
            "   Strength: {} (Score: {})",
            analysis.strength, analysis.score
        );
        println!("   Entropy: {:.1} bits", analysis.entropy);
        println!("   Time to crack: {}", analysis.time_to_crack);
        println!("   Feedback:");
        for feedback in &analysis.feedback {
            println!("     • {}", feedback);
        }
    }

    // Show policy requirements
    println!("\n📋 Corporate Policy Requirements:");
    println!("{}", corporate_policy.get_requirements());

    let high_sec_policy = HighSecurityPolicy::default();
    println!("\n📋 High-Security Policy Requirements:");
    println!("{}", high_sec_policy.get_requirements());
}
