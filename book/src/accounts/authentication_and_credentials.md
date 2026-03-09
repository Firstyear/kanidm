# Authentication and Credentials

A primary job of a system like Kanidm is to manage credentials for persons. This can involve a range of operations from
new user onboarding, credential resets, and self service.

## Types of Credentials

### Passkeys

This is the preferred method of authentication in Kanidm. Passkeys represent "all possible cryptographic" authenticators
that support Webauthn. Examples of this include Yubikeys, TouchID, Windows Hello, TPM's and more.

These devices are unphishable, self contained multifactor authenticators and are considered the most secure method of
authentication in Kanidm.

> [!WARNING]
>
> Kanidm's definition of Passkeys may differ from that of other systems. This is because we adopted the term very early,
> before it has changed and evolved.

### Attested Passkeys

These are the same as Passkeys, except that the device must present a cryptographic certificate or origin during
registration. This allows [account policy](account_policy.md) to be defined to only allow the use of certain models of
authenticator. In general only FIDO2 keys or TPM's are capable of meeting attestation requirements.

### Password + TOTP

This is a classic Time-based One Time Password combined with a password. Different to other systems Kanidm will prompt
for the TOTP _first_ before the password. This is to prevent drive by bruteforce against the password of the account and
testing if the password is vulnerable.

While this authentication method is mostly secure, we do not advise it for high security environments due to the fact it
is still possible to perform realtime phishing attacks.

## Resetting Person Account Credentials

Members of the groups `idm_people_admins`, `idm_people_on_boarding` and `idm_service_desk` have the rights to initiate a
credential reset for a person.

> NOTE: If the person is a member of `idm_high_privilege` then these resets are not allowed. This is to prevent
> `idm_service_desk` and similar roles from privilege escalation by resetting the credentials of a higher privileged
> account. If a person who is a member of `idm_high_privilege` requires a credential reset, this must be initiated by a
> member of `idm_people_admins`.

### Onboarding a New Person / Resetting Credentials

These processes are very similar. You can send a credential reset link to a user so that they can directly enroll their
own credentials. To generate this link or qrcode:

```bash
kanidm person credential create-reset-token <account_id> [<time to live in seconds>]
kanidm person credential create-reset-token demo_user --name idm_admin
kanidm person credential create-reset-token demo_user 86400 --name idm_admin
# The person can use one of the following to allow the credential reset
#
# Scan this QR Code:
#
# █████████████████████████████████████████████
# █████████████████████████████████████████████
# ████ ▄▄▄▄▄ █▄██ ▀▀▀▄▀▀█ ▄▀▀▀▀▄▀▀▄█ ▄▄▄▄▄ ████
# ████ █   █ █▀   ▄▄▄▀█  █▀ ██ ▀ ▀▄█ █   █ ████
# ████ █▄▄▄█ █ █▄█  ▀   ▄███▄ ▀▄▀▄ █ █▄▄▄█ ████
# ████▄▄▄▄▄▄▄█ █▄▀▄█▄█ █▄▀▄▀▄█▄█ █▄█▄▄▄▄▄▄▄████
# ████ ▀█▀ ▀▄▄▄ ▄▄▄▄▄▄▄█▀ ▄█▀█▀  ▄▀ ▄   █▀▄████
# ████▄ █ ▀ ▄█▀█ ▀█   ▀█▄ ▀█▀ ▄█▄ █▀▄▀██▄▀█████
# ████ ▀▀▀█▀▄██▄▀█ ▄▀█▄▄█▀▄▀▀▀▀▀▄▀▀▄▄▄▀ ▄▄ ████
# ████ █▄▀ ▄▄ ▄▀▀ ▀ █▄█ ▀▀ █▀▄▄█▄   ▀  ▄ ▀▀████
# ████ █▀▄ █▄▄  █ █▀▀█▀█▄ ▀█▄█▄█▀▄▄ ▀▀ ▄▄ ▄████
# █████ ▀█▄▀▄▄▀▀ ██▀▀█▄█▄█▄█ █▀▄█ ▄█  ▄▄▀▀█████
# ████▄▄▀  ▄▄ ▀▀▄▀▀ ▄▄█ ▄ █▄ ▄▄ ▀▀▀▄▄ ▀▄▄██████
# ████▄▄▀ ▀▀▄▀▄  ▀▀▀▀█▀█▄▀▀ ▄▄▄ ▄ ▄█▀  ▄ ▄ ████
# ████▀▄  ▀▄▄█▀█▀▄ ▄██▄█▀ ▄█▀█ ▀▄ ███▄█ ▄█▄████
# ██████ ▀▄█▄██▀ ▀█▄▀ ▀▀▄ ▀▀█ ██▀█▄▄▀██  ▀▀████
# ████▄▄██▄▄▄▄  ▀▄██▀█ ███▀ ██▄▀▀█ ▄▄▄ ███ ████
# ████ ▄▄▄▄▄ █▄ ▄▄  ▀█▀ ▀▀ █▀▄▄▄▄█ █▄█ ▀▀ ▀████
# ████ █   █ █▄█▄▀  ██▀█▄ ▀█▄▀▄ ▀▀▄   ▄▄▄▀ ████
# ████ █▄▄▄█ ██▀█ ▀▄▀█▄█▄█▄▀▀▄▄ ▀ ▄▄▄█▀█  █████
# ████▄▄▄▄▄▄▄█▄█▄▄▄▄▄▄█▄█▄██▄█▄▄▄█▄██▄███▄▄████
# █████████████████████████████████████████████
# ▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀
#
# This link: https://localhost:8443/ui/reset?token=8qDRG-AE1qC-zjjAT-0Fkd6
# Or run this command: kanidm person credential use-reset-token 8qDRG-AE1qC-zjjAT-0Fkd6
```

If the user wishes you can direct them to `https://idm.mydomain.name/ui/reset` where they can manually enter their token
value.

Once the credential reset has been committed the token is immediately invalidated and can never be used again. By
default the token is valid for 1 hour. You can request a longer token validity time when creating the token. Tokens are
only allowed to be valid for a maximum of 24 hours.

### Resetting Credentials Directly

You can perform a password reset on the `demo_user`, for example, as the `idm_admin` user, who is a default member of
this group. The lines below prefixed with `#` are the interactive credential update interface. This allows the user to
directly manage the credentials of another account.

> [!WARNING]
>
> Don't use the direct credential reset to lock or invalidate an account. You should expire the account instead.

```bash
kanidm person credential update demo_user --name idm_admin
# spn: demo_user@idm.example.com
# Name: Demonstration User
# Primary Credential:
# uuid: 0e19cd08-f943-489e-8ff2-69f9eacb1f31
# generated password: set
# Can Commit: true
#
# cred update (? for help) # : pass
# New password:
# New password: [hidden]
# Confirm password:
# Confirm password: [hidden]
# success
#
# cred update (? for help) # : commit
# Do you want to commit your changes? yes
# success
kanidm login --name demo_user
kanidm self whoami --name demo_user
```

## Credential Deletion

When a person deletes a credential, all sessions that were created by that credential are immediately logged out and
invalidated.

## Reauthentication / Privilege Access Mode

To allow for longer lived sessions in Kanidm, by default sessions are issued in a "privilege capable" but read-only
mode. In order to access privileges for a short time, you must re-authenticate. This re-issues your session with a small
time limited read-write session internally. You can consider this to be like `sudo` on a unix system or `UAC` on windows
where you reauthenticate for short periods to access higher levels of privilege.

When using a user command that requires these privileges you will be warned:

```shell
kanidm person credential update william
# Privileges have expired for william@idm.example.com - you need to re-authenticate again.
```

To reauthenticate

```shell
kanidm reauth -D william
```

> [!NOTE]
>
> During reauthentication an account must use the same credential that was used to initially authenticate to the
> session. The reauth flow will not allow any other credentials to be used!

## Password Changed Time

kanidm keeps track of the last time a password (relevant to logging in via LDAP/POSIX) was changed. This follows the [PrimaryCredFallback](../account_policy#setting-primary-credential-fallback) Policy, so if no Unix Credential is present, the last changed time of the Primary Credential will be used (if applicable).

This is credential will also be provided through LDAP via the `pwdChangedTime` attribute and is required for external applications to be informed on when a user has changed their credentials and needs to be re-authenticated. 