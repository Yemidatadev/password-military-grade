use crate::{CorporatePolicy, HighSecurityPolicy, PasswordManager, PolicyType};
use clap::{Parser, Subcommand};
use colored::*;

#[derive(Parser)]
#[command(name = "password-tool")]
#[command(about = "A comprehensive password generator and analyzer")]
pub struct Cli {
    #[command(subcommand)]
    pub command: Commands,
}

#[derive(Subcommand)]
pub enum Commands {
    /// Generate passwords
    Generate {
        /// Number of passwords to generate
        #[arg(short, long, default_value = "1")]
        count: usize,

        /// Policy to use (corporate, high-security)
        #[arg(short, long, default_value = "corporate")]
        policy: String,

        /// Show analysis for generated passwords
        #[arg(short, long)]
        analyze: bool,
    },

    /// Analyze password strength
    Analyze {
        /// Password to analyze (use quotes for spaces/symbols)
        password: String,

        /// Policy to use for analysis
        #[arg(short, long, default_value = "corporate")]
        policy: String,
    },

    /// Show policy requirements
    Requirements {
        /// Policy name to show requirements for
        #[arg(short, long, default_value = "corporate")]
        policy: String,
    },
}

pub fn run_cli() {
    let cli = Cli::parse();
    let manager = PasswordManager::new();

    match cli.command {
        Commands::Generate {
            count,
            policy,
            analyze,
        } => {
            println!(
                "{}",
                format!(
                    "🔐 Generating {} password(s) with {} policy:",
                    count, policy
                )
                .bold()
                .green()
            );

            let passwords = manager.generate_batch(count, Some(&policy));

            if passwords.is_empty() {
                eprintln!("{}", format!("❌ Unknown policy: {}", policy).red());
                eprintln!("Available policies: corporate, high-security");
                return;
            }

            for (i, password) in passwords.iter().enumerate() {
                println!("{}. {}", i + 1, password.bright_cyan());

                if analyze {
                    let policy_obj = get_policy(&policy);
                    let analysis = policy_obj.analyze_strength(password);
                    print_analysis(&analysis, false);
                    println!();
                }
            }
        }

        Commands::Analyze { password, policy } => {
            println!(
                "{}",
                format!("📊 Analyzing password strength with {} policy:", policy)
                    .bold()
                    .green()
            );
            println!("Password: {}", password.bright_cyan());

            let policy_obj = get_policy(&policy);
            let analysis = policy_obj.analyze_strength(&password);
            print_analysis(&analysis, true);
        }

        Commands::Requirements { policy } => {
            println!(
                "{}",
                format!("📋 {} Policy Requirements:", policy.to_uppercase())
                    .bold()
                    .green()
            );
            let policy_obj = get_policy(&policy);
            println!("{}", policy_obj.get_requirements());
        }
    }
}

fn get_policy(name: &str) -> PolicyType {
    match name {
        "corporate" => PolicyType::Corporate(CorporatePolicy::default()),
        "high-security" => PolicyType::HighSecurity(HighSecurityPolicy::default()),
        _ => {
            eprintln!("Unknown policy: {}, using corporate", name);
            PolicyType::Corporate(CorporatePolicy::default())
        }
    }
}

fn print_analysis(analysis: &crate::PasswordAnalysis, detailed: bool) {
    let strength_color = match analysis.strength {
        crate::StrengthLevel::VeryWeak => "red",
        crate::StrengthLevel::Weak => "red",
        crate::StrengthLevel::Fair => "yellow",
        crate::StrengthLevel::Good => "blue",
        crate::StrengthLevel::Strong => "green",
        crate::StrengthLevel::VeryStrong => "bright_green",
    };

    println!(
        "   Strength: {} (Score: {})",
        analysis.strength.to_string().color(strength_color).bold(),
        analysis.score
    );

    if detailed {
        println!("   Entropy: {:.1} bits", analysis.entropy);
        println!(
            "   Time to crack: {}",
            analysis.time_to_crack.bright_yellow()
        );

        println!("   Character composition:");
        let comp = &analysis.character_composition;
        println!("     • Length: {}", comp.length);
        println!(
            "     • Lowercase: {}",
            if comp.has_lowercase {
                "✓".green()
            } else {
                "✗".red()
            }
        );
        println!(
            "     • Uppercase: {}",
            if comp.has_uppercase {
                "✓".green()
            } else {
                "✗".red()
            }
        );
        println!(
            "     • Numbers: {}",
            if comp.has_numbers {
                "✓".green()
            } else {
                "✗".red()
            }
        );
        println!(
            "     • Symbols: {}",
            if comp.has_symbols {
                "✓".green()
            } else {
                "✗".red()
            }
        );
        println!("     • Unique chars: {}", comp.unique_chars);

        println!("   Feedback:");
        for feedback in &analysis.feedback {
            println!("     • {}", feedback.bright_blue());
        }
    }
}
