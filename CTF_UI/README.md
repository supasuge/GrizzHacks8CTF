# UI Directory layout plan

```bash
.
├── ctfapp
│   ├── blueprints
│   │   ├── admin
│   │   │   ├── routes.py
│   │   │   ├── forms.py
│   │   │   └── templates/admin
│   │   ├── auth
│   │   │   ├── routes.py
│   │   │   ├── forms.py
│   │   │   └── templates/auth
│   │   └── public
│   │       ├── routes.py
│   │       └── templates/public
│   ├── models
│   │   ├── user.py
│   │   ├── team.py
│   │   ├── principal.py
│   │   ├── challenge.py
│   │   ├── submission.py
│   │   ├── score.py
│   │   ├── rbac.py
│   │   └── event_log.py
│   ├── services
│   │   ├── auth_service.py
│   │   ├── team_service.py
│   │   ├── challenge_service.py
│   │   ├── challenge_importer.py
│   │   ├── flag_engine.py
│   │   ├── analytics_service.py
│   │   ├── mail_service.py
│   │   └── event_service.py
│   ├── security
│   │   ├── crypto.py
│   │   ├── tokens.py
│   │   ├── permissions.py
│   │   └── decorators.py
│   ├── static
│   ├── templates
│   │   ├── base.html
│   │   ├── footer.html
│   │   ├── error.html
│   │   └── index.html
│   ├── config.py
│   ├── errors.py
│   ├── extensions.py
│   └── __init__.py
├── migrations
├── instance
│   └── uploads
├── Dockerfile
├── start.sh
└── wsgi.py
```

---


| Entity                                 | Purpose                    | Key fields                                                                                                                              |
| -------------------------------------- | -------------------------- | --------------------------------------------------------------------------------------------------------------------------------------- |
| `users`                                | login/auth identity        | `id`, `public_id`, `email`, `username`, `password_hash`, `state`, `email_verified_at`, `auth_version`                                   |
| `teams`                                | team container             | `id`, `team_uid`, `name`, `captain_user_id`, `max_size=4`, `state`                                                                      |
| `team_members`                         | membership                 | `team_id`, `user_id`, `role(captain/member)`, `joined_at`, `active`                                                                     |
| `principals`                           | scoring identity           | `id`, `kind(team/solo)`, `public_id`, `fingerprint`, `team_id`, `user_id`, `active`                                                     |
| `roles` / `permissions` / `user_roles` | strict RBAC                | standard many-to-many permission model                                                                                                  |
| `challenges`                           | challenge metadata         | `id`, `category_slug`, `slug`, `title`, `points`, `description_md`, `flag_mode`, `runtime_type`, `flag_version`, `secret_enc`, `status` |
| `challenge_files`                      | uploaded assets            | `challenge_id`, `storage_path`, `filename`, `size`, `checksum`                                                                          |
| `submissions`                          | every attempt              | `id`, `principal_id`, `challenge_id`, `submitted_hash`, `result`, `detected_owner_principal_id`, `ip`, `ua`, `created_at`               |
| `solves`                               | accepted completions       | unique on `(principal_id, challenge_id)`, plus `points_awarded`, `solved_at`                                                            |
| `score_events`                         | append-only score ledger   | `principal_id`, `challenge_id`, `delta`, `reason`, `created_at`                                                                         |
| `participant_scores`                   | fast scoreboard read model | `principal_id`, `score_total`, `last_solve_at`                                                                                          |
| `email_verifications`                  | one-time verification      | `user_id`, `nonce_hash`, `expires_at`, `used_at`                                                                                        |
| `event_log`                            | monitoring + audit trail   | `type`, `severity`, `actor_user_id`, `principal_id`, `challenge_id`, `payload_json`, `prev_sig`, `sig`, `created_at`                    |

## Endpoints

