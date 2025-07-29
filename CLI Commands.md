> > > > > > > > > > > > > > > > ## Run with CLI commands

# Generate 5 passwords with corporate policy

cargo run -- generate -c 5 -p corporate

# Generate with analysis

cargo run -- generate -c 3 -p high-security --analyze

# Analyze a specific password

cargo run -- analyze "MyP@ssw0rd123!" -p corporate

# Show policy requirements

cargo run -- requirements -p high-security

# Show help

cargo run -- --help

> > > > > > > > > > > > > > > > > > > ## run the binary directly:

# Copy to a more convenient location (optional)

cp ./target/release/password_generator_strength_analyzer_tool.exe ./password-tool.exe

# Then run:

./password-tool.exe generate -c 5
./password-tool.exe analyze "TestPassword123!"
./password-tool.exe requirements
