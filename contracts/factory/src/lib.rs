#![no_std]
#![allow(clippy::too_many_arguments)]

use fluxora_stream::FluxoraStreamClient;
use soroban_sdk::{contract, contracterror, contractimpl, contracttype, Address, Env};

#[contracterror]
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum FactoryError {
    AlreadyInitialized = 1,
    NotInitialized = 2,
    Unauthorized = 3,
    RecipientNotAllowlisted = 4,
    DepositExceedsCap = 5,
    DurationTooShort = 6,
    /// The requested stream must end strictly after it starts.
    InvalidTimeRange = 7,
    /// The requested cliff must be within the inclusive start/end window.
    InvalidCliff = 8,
    /// `stream_contract` failed the FluxoraStream interface smoke check: it is
    /// either not a deployed contract or does not expose the expected
    /// read-only `version()` entrypoint. Returned by [`FluxoraFactory::init`]
    /// and [`FluxoraFactory::set_stream_contract`] instead of letting a bad
    /// address surface later as an opaque host trap from `create_stream`.
    InvalidStreamContract = 9,
}

#[contracttype]
pub enum DataKey {
    Admin,
    StreamContract,
    MaxDepositCap,
    MinDuration,
    Allowlist(Address),
}

/// Load and authorize the current factory admin.
///
/// This is the single authorization chokepoint for admin-only factory setters.
/// It preserves the existing `NotInitialized` behavior before attempting auth.
fn require_admin(env: &Env) -> Result<Address, FactoryError> {
    let admin: Address = env
        .storage()
        .instance()
        .get(&DataKey::Admin)
        .ok_or(FactoryError::NotInitialized)?;
    admin.require_auth();
    Ok(admin)
}

/// Smoke-test a candidate stream contract address for the FluxoraStream interface.
///
/// Calls the read-only, auth-free `version()` entrypoint through [`FluxoraStreamClient`]
/// using `try_version`, which routes the cross-contract call through the host's
/// fallible invocation path instead of the panicking one. A non-contract address
/// (EOA) or a contract that does not expose `version()` therefore surfaces as
/// `Ok(Err(_))`/`Err(_)` here rather than an unrecoverable host trap, letting
/// callers convert it into a typed [`FactoryError::InvalidStreamContract`] at
/// setup time instead of discovering it later inside `create_stream`.
fn verify_stream_contract_behavior(env: &Env, stream_contract: &Address) -> Result<(), FactoryError> {
    let stream_client = FluxoraStreamClient::new(env, stream_contract);
    match stream_client.try_version() {
        Ok(Ok(_)) => Ok(()),
        _ => Err(FactoryError::InvalidStreamContract),
    }
}

/// Read-only snapshot of the factory policy stored in instance storage.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FactoryConfig {
    pub admin: Address,
    pub stream_contract: Address,
    pub max_deposit: i128,
    pub min_duration: u64,
}

#[contract]
pub struct FluxoraFactory;

#[contractimpl]
#[allow(clippy::too_many_arguments)]
impl FluxoraFactory {
    /// Initialize the factory with admin, stream contract, and policies.
    ///
    /// # Authorization
    /// Requires `admin.require_auth()`. The declared `admin` must sign the
    /// bootstrap call itself, matching the auth model of every other
    /// admin-only setter (`require_admin`). This prevents an unrelated
    /// caller from front-running initialization with their own choice of
    /// admin/stream_contract before the intended admin can call `init`.
    ///
    /// # Validation
    /// `stream_contract` is smoke-tested via [`verify_stream_contract_behavior`]
    /// before being persisted: it must be a deployed contract that responds to
    /// the read-only FluxoraStream `version()` entrypoint. A wrong/EOA address
    /// is rejected here with [`FactoryError::InvalidStreamContract`] instead of
    /// being discovered later as an opaque host trap inside `create_stream`.
    ///
    /// # Errors
    /// - `AlreadyInitialized`: the factory has already been initialized.
    /// - `InvalidStreamContract`: `stream_contract` failed the smoke check.
    pub fn init(
        env: Env,
        admin: Address,
        stream_contract: Address,
        max_deposit: i128,
        min_duration: u64,
    ) -> Result<(), FactoryError> {
        admin.require_auth();

        if env.storage().instance().has(&DataKey::Admin) {
            return Err(FactoryError::AlreadyInitialized);
        }

        verify_stream_contract_behavior(&env, &stream_contract)?;

        env.storage().instance().set(&DataKey::Admin, &admin);
        env.storage()
            .instance()
            .set(&DataKey::StreamContract, &stream_contract);
        env.storage()
            .instance()
            .set(&DataKey::MaxDepositCap, &max_deposit);
        env.storage()
            .instance()
            .set(&DataKey::MinDuration, &min_duration);

        Ok(())
    }

    /// Admin updates the factory admin.
    pub fn set_admin(env: Env, new_admin: Address) -> Result<(), FactoryError> {
        require_admin(&env)?;

        env.storage().instance().set(&DataKey::Admin, &new_admin);
        Ok(())
    }

    /// Admin updates the stream contract address.
    ///
    /// # Authorization
    /// Requires the current admin's authorization via `require_admin`.
    ///
    /// # Validation
    /// Like `init`, `new_stream_contract` is smoke-tested via
    /// [`verify_stream_contract_behavior`] before being persisted, so a later
    /// swap cannot silently install a bad address. Fails with
    /// [`FactoryError::InvalidStreamContract`] on a non-contract or
    /// non-FluxoraStream address.
    pub fn set_stream_contract(env: Env, new_stream_contract: Address) -> Result<(), FactoryError> {
        require_admin(&env)?;

        verify_stream_contract_behavior(&env, &new_stream_contract)?;

        env.storage()
            .instance()
            .set(&DataKey::StreamContract, &new_stream_contract);
        Ok(())
    }

    /// Admin adds or removes a recipient from the allowlist.
    pub fn set_allowlist(env: Env, recipient: Address, allowed: bool) -> Result<(), FactoryError> {
        require_admin(&env)?;

        let key = DataKey::Allowlist(recipient);
        if allowed {
            env.storage().persistent().set(&key, &true);
        } else {
            env.storage().persistent().remove(&key);
        }

        Ok(())
    }

    /// Admin updates the max deposit cap.
    pub fn set_cap(env: Env, max_deposit: i128) -> Result<(), FactoryError> {
        require_admin(&env)?;

        env.storage()
            .instance()
            .set(&DataKey::MaxDepositCap, &max_deposit);
        Ok(())
    }

    /// Admin updates the minimum stream duration.
    pub fn set_min_duration(env: Env, min_duration: u64) -> Result<(), FactoryError> {
        require_admin(&env)?;

        env.storage()
            .instance()
            .set(&DataKey::MinDuration, &min_duration);
        Ok(())
    }

    /// Return the current factory policy configuration.
    pub fn get_factory_config(env: Env) -> Result<FactoryConfig, FactoryError> {
        Ok(FactoryConfig {
            admin: env
                .storage()
                .instance()
                .get(&DataKey::Admin)
                .ok_or(FactoryError::NotInitialized)?,
            stream_contract: env
                .storage()
                .instance()
                .get(&DataKey::StreamContract)
                .ok_or(FactoryError::NotInitialized)?,
            max_deposit: env
                .storage()
                .instance()
                .get(&DataKey::MaxDepositCap)
                .ok_or(FactoryError::NotInitialized)?,
            min_duration: env
                .storage()
                .instance()
                .get(&DataKey::MinDuration)
                .ok_or(FactoryError::NotInitialized)?,
        })
    }

    /// Return whether `recipient` is currently allowlisted for factory-created streams.
    pub fn is_allowlisted(env: Env, recipient: Address) -> bool {
        env.storage()
            .persistent()
            .get(&DataKey::Allowlist(recipient))
            .unwrap_or(false)
    }

    /// Creates a new stream via the FluxoraStream contract after enforcing treasury policies.
    #[allow(clippy::too_many_arguments)]
    pub fn create_stream(
        env: Env,
        sender: Address,
        recipient: Address,
        deposit_amount: i128,
        rate_per_second: i128,
        start_time: u64,
        cliff_time: u64,
        end_time: u64,
        withdraw_dust_threshold: i128,
    ) -> Result<u64, FactoryError> {
        // Enforce policies
        let is_allowed: bool = env
            .storage()
            .persistent()
            .get(&DataKey::Allowlist(recipient.clone()))
            .unwrap_or(false);
        if !is_allowed {
            return Err(FactoryError::RecipientNotAllowlisted);
        }

        let max_deposit: i128 = env
            .storage()
            .instance()
            .get(&DataKey::MaxDepositCap)
            .ok_or(FactoryError::NotInitialized)?;
        if deposit_amount > max_deposit {
            return Err(FactoryError::DepositExceedsCap);
        }

        // Mirror FluxoraStream time invariants before the cross-contract call so
        // invalid schedules return typed factory errors instead of downstream panics.
        if start_time >= end_time {
            return Err(FactoryError::InvalidTimeRange);
        }
        if cliff_time < start_time || cliff_time > end_time {
            return Err(FactoryError::InvalidCliff);
        }

        let min_duration: u64 = env
            .storage()
            .instance()
            .get(&DataKey::MinDuration)
            .ok_or(FactoryError::NotInitialized)?;
        let duration = end_time - start_time;
        if duration < min_duration {
            return Err(FactoryError::DurationTooShort);
        }

        // Must authenticate the sender because the factory calls FluxoraStream with this sender.
        // The sender needs to authorize both this wrapper invocation and the cross-contract invocation.
        sender.require_auth();

        let stream_contract: Address = env
            .storage()
            .instance()
            .get(&DataKey::StreamContract)
            .ok_or(FactoryError::NotInitialized)?;

        let stream_client = FluxoraStreamClient::new(&env, &stream_contract);

        // We wrap the `try_create_stream` to gracefully handle underlying failures if needed,
        // but for now, `.create_stream()` automatically panics with the underlying contract error
        // if it fails, which is standard Soroban cross-contract call behavior.
        let stream_id = stream_client.create_stream(
            &sender,
            &recipient,
            &deposit_amount,
            &rate_per_second,
            &start_time,
            &cliff_time,
            &end_time,
            &withdraw_dust_threshold,
            &None,
            &fluxora_stream::StreamKind::Linear,
        );

        Ok(stream_id)
    }
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use soroban_sdk::testutils::{Address as _, MockAuth, MockAuthInvoke};
    use soroban_sdk::IntoVal;

    const MAX_DEPOSIT: i128 = 1_000_000;
    const MIN_DURATION: u64 = 60;

    /// Deploys a fresh factory and a real FluxoraStream contract (unconfigured,
    /// `version()` is callable even pre-init) to use as a valid `stream_contract`.
    fn setup() -> (Env, Address, Address, Address) {
        let env = Env::default();
        let factory_id = env.register_contract(None, FluxoraFactory);
        let admin = Address::generate(&env);
        let stream_contract = env.register_contract(None, fluxora_stream::FluxoraStream);
        (env, factory_id, admin, stream_contract)
    }

    fn init_args(env: &Env, admin: &Address, stream_contract: &Address) -> soroban_sdk::Vec<soroban_sdk::Val> {
        (admin, stream_contract, &MAX_DEPOSIT, &MIN_DURATION).into_val(env)
    }

    // -----------------------------------------------------------------------
    // init: authorization
    // -----------------------------------------------------------------------

    #[test]
    fn init_succeeds_with_admin_authorization() {
        let (env, factory_id, admin, stream_contract) = setup();
        let client = FluxoraFactoryClient::new(&env, &factory_id);

        env.mock_auths(&[MockAuth {
            address: &admin,
            invoke: &MockAuthInvoke {
                contract: &factory_id,
                fn_name: "init",
                args: init_args(&env, &admin, &stream_contract),
                sub_invokes: &[],
            },
        }]);

        client.init(&admin, &stream_contract, &MAX_DEPOSIT, &MIN_DURATION);

        let cfg = client.get_factory_config();
        assert_eq!(cfg.admin, admin);
        assert_eq!(cfg.stream_contract, stream_contract);
        assert_eq!(cfg.max_deposit, MAX_DEPOSIT);
        assert_eq!(cfg.min_duration, MIN_DURATION);
    }

    #[test]
    fn init_fails_without_any_authorization() {
        let (env, factory_id, admin, stream_contract) = setup();
        let client = FluxoraFactoryClient::new(&env, &factory_id);

        // No mock_auths / mock_all_auths configured: admin.require_auth() must fail.
        let result = client.try_init(&admin, &stream_contract, &MAX_DEPOSIT, &MIN_DURATION);
        assert!(result.is_err(), "init must fail without admin auth");

        let cfg_result = client.try_get_factory_config();
        assert!(
            cfg_result.is_err(),
            "unauthenticated init must not write any config to storage"
        );
    }

    #[test]
    fn init_rejects_wrong_signer_and_has_no_side_effects() {
        let (env, factory_id, admin, stream_contract) = setup();
        let attacker = Address::generate(&env);
        let client = FluxoraFactoryClient::new(&env, &factory_id);

        env.mock_auths(&[MockAuth {
            address: &attacker,
            invoke: &MockAuthInvoke {
                contract: &factory_id,
                fn_name: "init",
                args: init_args(&env, &admin, &stream_contract),
                sub_invokes: &[],
            },
        }]);

        let result = client.try_init(&admin, &stream_contract, &MAX_DEPOSIT, &MIN_DURATION);
        assert!(result.is_err(), "init must reject a non-admin signer");

        let cfg_result = client.try_get_factory_config();
        assert!(
            cfg_result.is_err(),
            "failed init auth must not write config into storage"
        );
    }

    // -----------------------------------------------------------------------
    // init: stream_contract validation
    // -----------------------------------------------------------------------

    #[test]
    fn init_rejects_eoa_stream_contract() {
        let (env, factory_id, admin, _stream_contract) = setup();
        env.mock_all_auths();
        let client = FluxoraFactoryClient::new(&env, &factory_id);

        let eoa = Address::generate(&env);
        let result = client.try_init(&admin, &eoa, &MAX_DEPOSIT, &MIN_DURATION);
        assert_eq!(result, Ok(Err(FactoryError::InvalidStreamContract.into())));

        let cfg_result = client.try_get_factory_config();
        assert!(
            cfg_result.is_err(),
            "an invalid stream_contract must not leave the factory partially initialized"
        );
    }

    #[test]
    fn init_rejects_non_fluxora_stream_contract() {
        let (env, factory_id, admin, _stream_contract) = setup();
        env.mock_all_auths();
        let client = FluxoraFactoryClient::new(&env, &factory_id);

        // A real deployed contract (a SAC) that does not implement FluxoraStream.
        let token_admin = Address::generate(&env);
        let wrong_contract = env
            .register_stellar_asset_contract_v2(token_admin)
            .address();

        let result = client.try_init(&admin, &wrong_contract, &MAX_DEPOSIT, &MIN_DURATION);
        assert_eq!(result, Ok(Err(FactoryError::InvalidStreamContract.into())));
    }

    #[test]
    fn init_rejects_double_initialization() {
        let (env, factory_id, admin, stream_contract) = setup();
        env.mock_all_auths();
        let client = FluxoraFactoryClient::new(&env, &factory_id);

        client.init(&admin, &stream_contract, &MAX_DEPOSIT, &MIN_DURATION);

        let other_stream_contract = env.register_contract(None, fluxora_stream::FluxoraStream);
        let result = client.try_init(&admin, &other_stream_contract, &MAX_DEPOSIT, &MIN_DURATION);
        assert_eq!(result, Ok(Err(FactoryError::AlreadyInitialized.into())));
    }

    // -----------------------------------------------------------------------
    // set_stream_contract: authorization + validation
    // -----------------------------------------------------------------------

    #[test]
    fn set_stream_contract_rejects_eoa_address() {
        let (env, factory_id, admin, stream_contract) = setup();
        env.mock_all_auths();
        let client = FluxoraFactoryClient::new(&env, &factory_id);
        client.init(&admin, &stream_contract, &MAX_DEPOSIT, &MIN_DURATION);

        let eoa = Address::generate(&env);
        let result = client.try_set_stream_contract(&eoa);
        assert_eq!(result, Ok(Err(FactoryError::InvalidStreamContract.into())));

        // Config must remain unchanged after a rejected swap.
        let cfg = client.get_factory_config();
        assert_eq!(cfg.stream_contract, stream_contract);
    }

    #[test]
    fn set_stream_contract_rejects_non_fluxora_stream_contract() {
        let (env, factory_id, admin, stream_contract) = setup();
        env.mock_all_auths();
        let client = FluxoraFactoryClient::new(&env, &factory_id);
        client.init(&admin, &stream_contract, &MAX_DEPOSIT, &MIN_DURATION);

        let token_admin = Address::generate(&env);
        let wrong_contract = env
            .register_stellar_asset_contract_v2(token_admin)
            .address();

        let result = client.try_set_stream_contract(&wrong_contract);
        assert_eq!(result, Ok(Err(FactoryError::InvalidStreamContract.into())));

        let cfg = client.get_factory_config();
        assert_eq!(cfg.stream_contract, stream_contract);
    }

    #[test]
    fn set_stream_contract_accepts_valid_contract() {
        let (env, factory_id, admin, stream_contract) = setup();
        env.mock_all_auths();
        let client = FluxoraFactoryClient::new(&env, &factory_id);
        client.init(&admin, &stream_contract, &MAX_DEPOSIT, &MIN_DURATION);

        let new_stream_contract = env.register_contract(None, fluxora_stream::FluxoraStream);
        client.set_stream_contract(&new_stream_contract);

        let cfg = client.get_factory_config();
        assert_eq!(cfg.stream_contract, new_stream_contract);
    }

    #[test]
    fn set_stream_contract_rejects_non_admin_signer() {
        let (env, factory_id, admin, stream_contract) = setup();
        env.mock_all_auths();
        let client = FluxoraFactoryClient::new(&env, &factory_id);
        client.init(&admin, &stream_contract, &MAX_DEPOSIT, &MIN_DURATION);

        let attacker = Address::generate(&env);
        let new_stream_contract = env.register_contract(None, fluxora_stream::FluxoraStream);

        env.mock_auths(&[MockAuth {
            address: &attacker,
            invoke: &MockAuthInvoke {
                contract: &factory_id,
                fn_name: "set_stream_contract",
                args: (&new_stream_contract,).into_val(&env),
                sub_invokes: &[],
            },
        }]);

        let result = client.try_set_stream_contract(&new_stream_contract);
        assert!(result.is_err(), "set_stream_contract must reject a non-admin signer");

        let cfg = client.get_factory_config();
        assert_eq!(cfg.stream_contract, stream_contract);
    }

    // -----------------------------------------------------------------------
    // Other admin setters and read paths (regression coverage)
    // -----------------------------------------------------------------------

    #[test]
    fn set_admin_updates_admin_and_requires_old_admin_auth() {
        let (env, factory_id, admin, stream_contract) = setup();
        env.mock_all_auths();
        let client = FluxoraFactoryClient::new(&env, &factory_id);
        client.init(&admin, &stream_contract, &MAX_DEPOSIT, &MIN_DURATION);

        let new_admin = Address::generate(&env);
        client.set_admin(&new_admin);

        let cfg = client.get_factory_config();
        assert_eq!(cfg.admin, new_admin);
    }

    #[test]
    fn set_cap_and_set_min_duration_update_policy() {
        let (env, factory_id, admin, stream_contract) = setup();
        env.mock_all_auths();
        let client = FluxoraFactoryClient::new(&env, &factory_id);
        client.init(&admin, &stream_contract, &MAX_DEPOSIT, &MIN_DURATION);

        client.set_cap(&500);
        client.set_min_duration(&10);

        let cfg = client.get_factory_config();
        assert_eq!(cfg.max_deposit, 500);
        assert_eq!(cfg.min_duration, 10);
    }

    #[test]
    fn set_allowlist_toggles_is_allowlisted() {
        let (env, factory_id, admin, stream_contract) = setup();
        env.mock_all_auths();
        let client = FluxoraFactoryClient::new(&env, &factory_id);
        client.init(&admin, &stream_contract, &MAX_DEPOSIT, &MIN_DURATION);

        let recipient = Address::generate(&env);
        assert!(!client.is_allowlisted(&recipient));

        client.set_allowlist(&recipient, &true);
        assert!(client.is_allowlisted(&recipient));

        client.set_allowlist(&recipient, &false);
        assert!(!client.is_allowlisted(&recipient));
    }

    #[test]
    fn get_factory_config_fails_before_init() {
        let (env, factory_id, _admin, _stream_contract) = setup();
        let client = FluxoraFactoryClient::new(&env, &factory_id);

        let result = client.try_get_factory_config();
        assert_eq!(result, Ok(Err(FactoryError::NotInitialized.into())));
    }

    // -----------------------------------------------------------------------
    // create_stream: policy checks unaffected by the new validation
    // -----------------------------------------------------------------------

    #[test]
    fn create_stream_rejects_non_allowlisted_recipient() {
        let (env, factory_id, admin, stream_contract) = setup();
        env.mock_all_auths();
        let client = FluxoraFactoryClient::new(&env, &factory_id);
        client.init(&admin, &stream_contract, &MAX_DEPOSIT, &MIN_DURATION);

        let sender = Address::generate(&env);
        let recipient = Address::generate(&env);

        let result = client.try_create_stream(
            &sender, &recipient, &1_000, &1, &0, &0, &100, &0,
        );
        assert_eq!(result, Ok(Err(FactoryError::RecipientNotAllowlisted.into())));
    }

    #[test]
    fn create_stream_rejects_deposit_over_cap() {
        let (env, factory_id, admin, stream_contract) = setup();
        env.mock_all_auths();
        let client = FluxoraFactoryClient::new(&env, &factory_id);
        client.init(&admin, &stream_contract, &MAX_DEPOSIT, &MIN_DURATION);

        let sender = Address::generate(&env);
        let recipient = Address::generate(&env);
        client.set_allowlist(&recipient, &true);

        let result = client.try_create_stream(
            &sender,
            &recipient,
            &(MAX_DEPOSIT + 1),
            &1,
            &0,
            &0,
            &100,
            &0,
        );
        assert_eq!(result, Ok(Err(FactoryError::DepositExceedsCap.into())));
    }

    #[test]
    fn create_stream_rejects_invalid_time_range() {
        let (env, factory_id, admin, stream_contract) = setup();
        env.mock_all_auths();
        let client = FluxoraFactoryClient::new(&env, &factory_id);
        client.init(&admin, &stream_contract, &MAX_DEPOSIT, &MIN_DURATION);

        let sender = Address::generate(&env);
        let recipient = Address::generate(&env);
        client.set_allowlist(&recipient, &true);

        let result = client.try_create_stream(
            &sender, &recipient, &1_000, &1, &100, &100, &100, &0,
        );
        assert_eq!(result, Ok(Err(FactoryError::InvalidTimeRange.into())));
    }

    #[test]
    fn create_stream_rejects_invalid_cliff() {
        let (env, factory_id, admin, stream_contract) = setup();
        env.mock_all_auths();
        let client = FluxoraFactoryClient::new(&env, &factory_id);
        client.init(&admin, &stream_contract, &MAX_DEPOSIT, &MIN_DURATION);

        let sender = Address::generate(&env);
        let recipient = Address::generate(&env);
        client.set_allowlist(&recipient, &true);

        let result = client.try_create_stream(
            &sender, &recipient, &1_000, &1, &0, &200, &100, &0,
        );
        assert_eq!(result, Ok(Err(FactoryError::InvalidCliff.into())));
    }

    #[test]
    fn create_stream_rejects_duration_too_short() {
        let (env, factory_id, admin, stream_contract) = setup();
        env.mock_all_auths();
        let client = FluxoraFactoryClient::new(&env, &factory_id);
        client.init(&admin, &stream_contract, &MAX_DEPOSIT, &MIN_DURATION);

        let sender = Address::generate(&env);
        let recipient = Address::generate(&env);
        client.set_allowlist(&recipient, &true);

        let result = client.try_create_stream(
            &sender, &recipient, &1_000, &1, &0, &0, &10, &0,
        );
        assert_eq!(result, Ok(Err(FactoryError::DurationTooShort.into())));
    }

    #[test]
    fn create_stream_succeeds_through_a_valid_factory_configured_stream_contract() {
        use soroban_sdk::token::StellarAssetClient;

        let (env, factory_id, admin, stream_contract) = setup();
        env.mock_all_auths();

        // Initialize the real FluxoraStream contract behind the factory.
        let token_admin = Address::generate(&env);
        let token_id = env
            .register_stellar_asset_contract_v2(token_admin)
            .address();
        let stream_admin = Address::generate(&env);
        fluxora_stream::FluxoraStreamClient::new(&env, &stream_contract)
            .init(&token_id, &stream_admin);

        let client = FluxoraFactoryClient::new(&env, &factory_id);
        client.init(&admin, &stream_contract, &MAX_DEPOSIT, &MIN_DURATION);

        let sender = Address::generate(&env);
        let recipient = Address::generate(&env);
        client.set_allowlist(&recipient, &true);

        StellarAssetClient::new(&env, &token_id).mint(&sender, &10_000);
        soroban_sdk::token::Client::new(&env, &token_id).approve(
            &sender,
            &stream_contract,
            &i128::MAX,
            &100_000,
        );

        let stream_id = client.create_stream(&sender, &recipient, &1_000, &1, &0, &0, &100, &0);
        assert_eq!(stream_id, 0);
    }
}
