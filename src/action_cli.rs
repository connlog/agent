use anyhow::{Context, Result};
use std::io::{self, IsTerminal, Write};

use crate::config::{
    ActionCommand, AddActionArgs, CliActionOutputMode, CliActionRisk, RegisterActionArgs,
};
use crate::quick_actions::{
    command_looks_risky, is_valid_action_id, label_to_action_id, parse_command_line,
    register_local_action, remove_local_action, set_local_action_enabled, OutputMode,
    QuickActionRegistration, QuickActionRequest, QuickActionsRegistry, Risk,
    DEFAULT_ACTION_CATEGORY, DEFAULT_MAX_OUTPUT_BYTES, DEFAULT_TIMEOUT_SECONDS,
    MAX_TIMEOUT_SECONDS,
};

pub fn run_action_command(command: ActionCommand) -> Result<()> {
    match command {
        ActionCommand::Add(args) => add_cli_action(args),
        ActionCommand::Register(args) => register_cli_action(args),
        ActionCommand::List => list_cli_actions(),
        ActionCommand::Remove { action_id } => {
            let path = remove_local_action(&action_id)?;
            println!("Removed local action `{action_id}` from {}", path.display());
            println!("The dashboard will update after the agent's next heartbeat.");
            Ok(())
        }
        ActionCommand::Enable { action_id } => {
            let path = set_local_action_enabled(&action_id, true)?;
            println!("Enabled local action `{action_id}` in {}", path.display());
            println!("The dashboard will update after the agent's next heartbeat.");
            Ok(())
        }
        ActionCommand::Disable { action_id } => {
            let path = set_local_action_enabled(&action_id, false)?;
            println!("Disabled local action `{action_id}` in {}", path.display());
            println!("The dashboard will update after the agent's next heartbeat.");
            Ok(())
        }
        ActionCommand::Test { action_id } => test_cli_action(&action_id),
    }
}

fn list_cli_actions() -> Result<()> {
    let registry = QuickActionsRegistry::load();
    let actions = registry.actions();
    if actions.is_empty() {
        println!("No local actions registered.");
        println!("Add one with: sudo connlog-agent action add");
        return Ok(());
    }

    println!("Local dashboard actions:");
    for action in actions {
        println!(
            "  {}  {}  {}  risk={} output={} timeout={}s max_output={}B",
            action.id,
            action.label,
            if action.enabled {
                "enabled"
            } else {
                "disabled"
            },
            action.risk.as_str(),
            action.output_mode.as_str(),
            action.timeout_seconds,
            action.max_output_bytes
        );
    }
    Ok(())
}

fn test_cli_action(action_id: &str) -> Result<()> {
    let registry = QuickActionsRegistry::load();
    registry
        .action(action_id)
        .with_context(|| format!("local action `{action_id}` is not registered"))?;

    let result = registry.execute(&QuickActionRequest {
        request_id: "00000000-0000-0000-0000-000000000001".to_string(),
        action_id: action_id.to_string(),
    });

    println!(
        "Action `{action_id}` finished with status: {}",
        result.status
    );
    if let Some(exit_code) = result.exit_code {
        println!("Exit code: {exit_code}");
    }
    if result.truncated {
        println!("Output was truncated.");
    }
    if let Some(stdout) = result.stdout {
        println!("\nstdout:\n{stdout}");
    }
    if let Some(stderr) = result.stderr {
        println!("\nstderr:\n{stderr}");
    }
    Ok(())
}

fn add_cli_action(args: AddActionArgs) -> Result<()> {
    if args_needs_prompt(
        args.action_id.as_deref(),
        args.label.as_deref(),
        &args.exec,
        add_args_has_any_input(&args),
    ) {
        return interactive_register_action(false);
    }

    let registration = registration_from_add_args(args)?;
    ensure_new_action_id(&registration.id)?;
    write_registration(registration)
}

fn register_cli_action(args: RegisterActionArgs) -> Result<()> {
    if args_needs_prompt(
        args.action_id.as_deref(),
        args.label.as_deref(),
        &args.exec,
        register_args_has_any_input(&args),
    ) {
        return interactive_register_action(true);
    }

    let registration = registration_from_register_args(args)?;
    write_registration(registration)
}

fn args_needs_prompt(
    action_id: Option<&str>,
    label: Option<&str>,
    exec: &[String],
    has_any_input: bool,
) -> bool {
    if action_id.is_none() && label.is_none() && exec.is_empty() {
        return true;
    }

    let incomplete = label.is_none() || exec.is_empty();
    incomplete && io::stdin().is_terminal() && !has_any_input
}

fn add_args_has_any_input(args: &AddActionArgs) -> bool {
    args.action_id.is_some()
        || args.label.is_some()
        || args.description.is_some()
        || args.category.is_some()
        || args.risk.is_some()
        || args.requires_confirmation
        || args.no_confirmation
        || args.output
        || args.no_output
        || args.output_mode.is_some()
        || args.timeout_seconds.is_some()
        || args.max_output_bytes.is_some()
        || !args.exec.is_empty()
}

fn register_args_has_any_input(args: &RegisterActionArgs) -> bool {
    args.action_id.is_some()
        || args.label.is_some()
        || args.description.is_some()
        || args.category.is_some()
        || args.risk.is_some()
        || args.requires_confirmation
        || args.no_confirmation
        || args.output
        || args.no_output
        || args.output_mode.is_some()
        || args.timeout_seconds.is_some()
        || args.max_output_bytes.is_some()
        || !args.exec.is_empty()
}

fn registration_from_add_args(args: AddActionArgs) -> Result<QuickActionRegistration> {
    let label = clean_required(args.label, "label")?;
    let id = match args.action_id {
        Some(action_id) => clean_action_id(action_id)?,
        None => generated_action_id(&label)?,
    };
    registration_from_parts(RegistrationParts {
        id,
        label,
        description: args.description,
        category: args.category,
        risk: args.risk,
        requires_confirmation: args.requires_confirmation,
        no_confirmation: args.no_confirmation,
        output: args.output,
        no_output: args.no_output,
        output_mode: args.output_mode,
        timeout_seconds: args.timeout_seconds,
        max_output_bytes: args.max_output_bytes,
        exec: args.exec,
    })
}

fn registration_from_register_args(args: RegisterActionArgs) -> Result<QuickActionRegistration> {
    let label = clean_required(args.label, "label")?;
    let id = match args.action_id {
        Some(action_id) => clean_action_id(action_id)?,
        None => generated_action_id(&label)?,
    };
    registration_from_parts(RegistrationParts {
        id,
        label,
        description: args.description,
        category: args.category,
        risk: args.risk,
        requires_confirmation: args.requires_confirmation,
        no_confirmation: args.no_confirmation,
        output: args.output,
        no_output: args.no_output,
        output_mode: args.output_mode,
        timeout_seconds: args.timeout_seconds,
        max_output_bytes: args.max_output_bytes,
        exec: args.exec,
    })
}

struct RegistrationParts {
    id: String,
    label: String,
    description: Option<String>,
    category: Option<String>,
    risk: Option<CliActionRisk>,
    requires_confirmation: bool,
    no_confirmation: bool,
    output: bool,
    no_output: bool,
    output_mode: Option<CliActionOutputMode>,
    timeout_seconds: Option<u64>,
    max_output_bytes: Option<usize>,
    exec: Vec<String>,
}

fn registration_from_parts(parts: RegistrationParts) -> Result<QuickActionRegistration> {
    if parts.exec.is_empty() || parts.exec.iter().any(|part| part.trim().is_empty()) {
        anyhow::bail!("command argv must contain at least one non-empty value");
    }

    let risky = command_looks_risky(&parts.exec);
    let risk = parts
        .risk
        .map(cli_risk)
        .unwrap_or(if risky { Risk::High } else { Risk::Medium });
    let requires_confirmation = if parts.no_confirmation {
        false
    } else {
        parts.requires_confirmation || risky
    };
    let output_mode = match parts.output_mode {
        Some(mode) => cli_output_mode(mode),
        None if parts.output => OutputMode::Ephemeral,
        None if parts.no_output => OutputMode::Hidden,
        None => OutputMode::Hidden,
    };

    Ok(QuickActionRegistration {
        id: parts.id,
        label: parts.label,
        description: clean_optional(parts.description),
        category: clean_optional(parts.category).or_else(|| Some(DEFAULT_ACTION_CATEGORY.into())),
        risk,
        requires_confirmation,
        enabled: true,
        timeout_seconds: parts.timeout_seconds.unwrap_or(DEFAULT_TIMEOUT_SECONDS),
        output_mode,
        max_output_bytes: parts.max_output_bytes.unwrap_or(DEFAULT_MAX_OUTPUT_BYTES),
        exec: parts.exec,
    })
}

fn interactive_register_action(allow_replace: bool) -> Result<()> {
    if !io::stdin().is_terminal() {
        anyhow::bail!(
            "interactive action setup needs a terminal; for scripts use `connlog-agent action add <id> --label <label> -- <command> [args...]`"
        );
    }

    let registry = QuickActionsRegistry::load();
    let (label, id) = prompt_label_and_unique_id(&registry, allow_replace)?;

    let description = clean_optional(Some(prompt_line("Description:", false)?));
    let command_line = prompt_line("Command to run:", true)?;
    let exec = parse_command_line(&command_line)?;
    let output_mode = if prompt_bool("Show output in dashboard?", true)? {
        OutputMode::Ephemeral
    } else {
        OutputMode::Hidden
    };
    let risky = command_looks_risky(&exec);
    let requires_confirmation = if risky {
        println!("\nThis command may change system state.");
        prompt_bool(
            "Require confirmation before running from the dashboard?",
            true,
        )?
    } else {
        prompt_bool("Require confirmation before running?", false)?
    };

    let registration = QuickActionRegistration {
        id,
        label,
        description,
        category: Some(DEFAULT_ACTION_CATEGORY.into()),
        risk: if risky { Risk::High } else { Risk::Medium },
        requires_confirmation,
        enabled: true,
        timeout_seconds: DEFAULT_TIMEOUT_SECONDS,
        output_mode,
        max_output_bytes: DEFAULT_MAX_OUTPUT_BYTES,
        exec,
    };

    write_registration(registration)
}

fn prompt_label_and_unique_id(
    registry: &QuickActionsRegistry,
    allow_replace: bool,
) -> Result<(String, String)> {
    let mut label = prompt_line("Button label:", true)?;

    loop {
        let id = generated_action_id(&label)?;
        if allow_replace || !registry.has_action(&id) {
            return Ok((label, id));
        }

        println!("\nAn action with ID `{id}` already exists.");
        let input = prompt_line("Enter a different label or a custom ID:", true)?;
        if is_custom_id_input(&input) {
            let id = clean_action_id(input)?;
            if allow_replace || !registry.has_action(&id) {
                return Ok((label, id));
            }
            println!("\nAn action with ID `{id}` already exists.");
        } else {
            label = input;
        }
    }
}

fn prompt_line(label: &str, required: bool) -> Result<String> {
    loop {
        println!("\n{label}");
        print!("> ");
        io::stdout().flush().context("failed to flush prompt")?;

        let mut value = String::new();
        io::stdin()
            .read_line(&mut value)
            .context("failed to read prompt input")?;
        let value = value.trim().to_string();
        if !required || !value.is_empty() {
            return Ok(value);
        }
        println!("Please enter a value.");
    }
}

fn prompt_bool(label: &str, default: bool) -> Result<bool> {
    let suffix = if default { "[Y/n]" } else { "[y/N]" };
    loop {
        println!("\n{label} {suffix}:");
        print!("> ");
        io::stdout().flush().context("failed to flush prompt")?;

        let mut value = String::new();
        io::stdin()
            .read_line(&mut value)
            .context("failed to read prompt input")?;
        let value = value.trim().to_ascii_lowercase();
        match value.as_str() {
            "" => return Ok(default),
            "y" | "yes" => return Ok(true),
            "n" | "no" => return Ok(false),
            _ => println!("Please answer y or n."),
        }
    }
}

fn ensure_new_action_id(action_id: &str) -> Result<()> {
    if QuickActionsRegistry::load().has_action(action_id) {
        anyhow::bail!(
            "local action `{action_id}` already exists; choose another ID or use `actions register` to replace it"
        );
    }
    Ok(())
}

fn write_registration(registration: QuickActionRegistration) -> Result<()> {
    validate_registration(&registration)?;
    let summary = RegistrationSummary::from(&registration);
    register_local_action(registration)?;
    print_success(summary);
    Ok(())
}

fn validate_registration(registration: &QuickActionRegistration) -> Result<()> {
    if registration.label.trim().is_empty() {
        anyhow::bail!("label must not be empty");
    }
    if !is_valid_action_id(&registration.id) {
        anyhow::bail!("generated action id `{}` is not valid", registration.id);
    }
    if registration.exec.is_empty() || registration.exec.iter().any(|part| part.trim().is_empty()) {
        anyhow::bail!("command must not be empty");
    }
    if registration.timeout_seconds == 0 || registration.timeout_seconds > MAX_TIMEOUT_SECONDS {
        anyhow::bail!("timeout must be between 1 and {MAX_TIMEOUT_SECONDS} seconds");
    }
    if registration.max_output_bytes == 0
        || registration.max_output_bytes > crate::quick_actions::HARD_MAX_OUTPUT_BYTES
    {
        anyhow::bail!(
            "max output bytes must be between 1 and {}",
            crate::quick_actions::HARD_MAX_OUTPUT_BYTES
        );
    }
    Ok(())
}

struct RegistrationSummary {
    id: String,
    label: String,
    command: String,
    output: &'static str,
    confirmation: &'static str,
}

impl From<&QuickActionRegistration> for RegistrationSummary {
    fn from(action: &QuickActionRegistration) -> Self {
        Self {
            id: action.id.clone(),
            label: action.label.clone(),
            command: display_command(&action.exec),
            output: match action.output_mode {
                OutputMode::Ephemeral => "shown in dashboard",
                OutputMode::Hidden => "hidden",
            },
            confirmation: if action.requires_confirmation {
                "required"
            } else {
                "not required"
            },
        }
    }
}

fn print_success(summary: RegistrationSummary) {
    println!("\nAction registered.\n");
    println!("ID: {}", summary.id);
    println!("Label: {}", summary.label);
    println!("Command: {}", summary.command);
    println!("Output: {}", summary.output);
    println!("Confirmation: {}", summary.confirmation);
    println!("\nThis action will appear in ConnLog after the next heartbeat.");
}

fn clean_required(value: Option<String>, name: &str) -> Result<String> {
    let Some(value) = clean_optional(value) else {
        anyhow::bail!("{name} must not be empty");
    };
    Ok(value)
}

fn clean_optional(value: Option<String>) -> Option<String> {
    value
        .map(|value| value.trim().to_string())
        .filter(|v| !v.is_empty())
}

fn generated_action_id(label: &str) -> Result<String> {
    let action_id = label_to_action_id(label);
    if action_id.is_empty() || !is_valid_action_id(&action_id) {
        anyhow::bail!("could not generate a valid action ID from `{label}`");
    }
    Ok(action_id)
}

fn clean_action_id(action_id: String) -> Result<String> {
    let action_id = action_id.trim().to_string();
    if !is_valid_action_id(&action_id) {
        anyhow::bail!("action id `{action_id}` must use letters, numbers, _, -, ., or :");
    }
    Ok(action_id)
}

fn is_custom_id_input(value: &str) -> bool {
    let value = value.trim();
    !value.contains(char::is_whitespace)
        && value.chars().any(|ch| matches!(ch, '_' | '-' | '.' | ':'))
        && is_valid_action_id(value)
}

fn display_command(exec: &[String]) -> String {
    exec.iter()
        .map(|part| {
            if part
                .chars()
                .all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '_' | '-' | '.' | '/' | ':'))
            {
                part.clone()
            } else {
                format!("\"{}\"", part.replace('\\', "\\\\").replace('"', "\\\""))
            }
        })
        .collect::<Vec<_>>()
        .join(" ")
}

fn cli_risk(risk: CliActionRisk) -> Risk {
    match risk {
        CliActionRisk::Low => Risk::Low,
        CliActionRisk::Medium => Risk::Medium,
        CliActionRisk::High => Risk::High,
    }
}

fn cli_output_mode(mode: CliActionOutputMode) -> OutputMode {
    match mode {
        CliActionOutputMode::Hidden => OutputMode::Hidden,
        CliActionOutputMode::Ephemeral => OutputMode::Ephemeral,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::sync::Mutex;
    use std::time::{SystemTime, UNIX_EPOCH};

    static ENV_LOCK: Mutex<()> = Mutex::new(());

    #[test]
    fn generated_ids_are_stable_snake_case() {
        assert_eq!(
            generated_action_id("Check disk usage").unwrap(),
            "check_disk_usage"
        );
        assert_eq!(
            generated_action_id("  Docker: ps -a! ").unwrap(),
            "docker_ps_a"
        );
    }

    #[test]
    fn non_interactive_add_defaults_are_safe() {
        let registration = registration_from_add_args(AddActionArgs {
            action_id: None,
            label: Some("Check disk usage".to_string()),
            description: Some("Shows current disk usage".to_string()),
            category: None,
            risk: None,
            requires_confirmation: false,
            no_confirmation: false,
            output: true,
            no_output: false,
            output_mode: None,
            timeout_seconds: None,
            max_output_bytes: None,
            exec: vec!["df".to_string(), "-h".to_string()],
        })
        .expect("registration builds");

        assert_eq!(registration.id, "check_disk_usage");
        assert_eq!(
            registration.category.as_deref(),
            Some(DEFAULT_ACTION_CATEGORY)
        );
        assert_eq!(registration.risk, Risk::Medium);
        assert!(!registration.requires_confirmation);
        assert_eq!(registration.output_mode, OutputMode::Ephemeral);
        assert_eq!(registration.timeout_seconds, DEFAULT_TIMEOUT_SECONDS);
        assert_eq!(registration.max_output_bytes, DEFAULT_MAX_OUTPUT_BYTES);
    }

    #[test]
    fn risky_commands_default_to_confirmation() {
        let registration = registration_from_add_args(AddActionArgs {
            action_id: Some("restart_nginx".to_string()),
            label: Some("Restart nginx".to_string()),
            description: None,
            category: None,
            risk: None,
            requires_confirmation: false,
            no_confirmation: false,
            output: false,
            no_output: false,
            output_mode: None,
            timeout_seconds: None,
            max_output_bytes: None,
            exec: vec![
                "systemctl".to_string(),
                "restart".to_string(),
                "nginx".to_string(),
            ],
        })
        .expect("registration builds");

        assert_eq!(registration.risk, Risk::High);
        assert!(registration.requires_confirmation);
    }

    #[test]
    fn timeout_above_sixty_seconds_is_rejected() {
        let registration = registration_from_add_args(AddActionArgs {
            action_id: Some("slow".to_string()),
            label: Some("Slow".to_string()),
            description: None,
            category: None,
            risk: None,
            requires_confirmation: false,
            no_confirmation: false,
            output: false,
            no_output: false,
            output_mode: None,
            timeout_seconds: Some(61),
            max_output_bytes: None,
            exec: vec!["sleep".to_string(), "1".to_string()],
        })
        .expect("registration builds before validation");

        assert!(validate_registration(&registration).is_err());
    }

    #[test]
    fn duplicate_action_id_is_rejected_for_action_add() {
        let _guard = ENV_LOCK.lock().expect("env lock");
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock works")
            .as_nanos();
        let path = std::env::temp_dir().join(format!("connlog-actions-{unique}.toml"));
        fs::write(
            &path,
            r#"
[quick_actions]
enabled = true

[quick_actions.disk_usage]
label = "Check disk usage"
exec = ["df", "-h"]
"#,
        )
        .expect("write temp actions config");
        std::env::set_var("CONNLOG_QUICK_ACTIONS_CONFIG", &path);

        let result = ensure_new_action_id("disk_usage");

        std::env::remove_var("CONNLOG_QUICK_ACTIONS_CONFIG");
        let _ = fs::remove_file(path);
        assert!(result.is_err());
    }
}
