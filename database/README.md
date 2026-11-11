# ArS course demo backend
Project: ars-elite-cakes (`iwddnwbsrejhqpwnixig`). Region: eu-central-1.

Applied schema is in `ars-schema.sql`; illustrative catalogue/lesson/payment data are in `ars-seed.sql`. Do not reapply the seed to an existing populated database. Migrations have already been applied through the Supabase connector.

Private administrator membership is assigned only by the project operator in `private.admin_users`, never from user_metadata or from client-side controls. Public tables have RLS and explicit grants. Purchase/review wrappers check the authenticated UUID; approval updates the request and grants the entitlement atomically. Lesson metadata is only readable by the enrolled learner or an administrator.

`functions/ars-register/index.ts` is the deployed public registration endpoint. It keeps the service-role secret in the Edge runtime, validates inputs, limits registrations, and intentionally confirms email immediately for the requested demo flow. No emails are sent. Public API configuration in the frontend is not a secret.

End-to-end REST checks confirmed: public metadata; unauthenticated lesson denial; student-only request visibility; rejection of non-admin approval and direct enrolment writes; unchanged prices after unauthorised updates; idempotent purchase requests; owner approval unlocking the enrolled learner's lesson while a different account remains blocked. Void review RPCs return HTTP 204 on success.

This is a demo. There are no real payment details, automated bank checks or protected production streaming. All teaching/pricing content requires business approval.
