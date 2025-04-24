# Estructura del Proyecto

```
├── logs
└── src
    ├── app.ts
    ├── config
    │   ├── db.ts
    │   └── mailer.ts
    ├── domain
    │   ├── models
    │   │   └── user
    │   │       ├── cart.model.ts
    │   │       ├── cartItem.model.ts
    │   │       ├── permission.model.ts
    │   │       ├── role.model.ts
    │   │       ├── service.model.ts
    │   │       └── user.model.ts
    │   ├── ports
    │   │   ├── role.repository.ts
    │   │   └── user.repository.ts
    │   └── services
    │       └── auth
    │           ├── auth.service.ts
    │           ├── confirm.service.ts
    │           └── recovery.service.ts
    ├── index.ts
    ├── infraestructure
    │   ├── db
    │   │   ├── role.repository.ts
    │   │   └── user.repository.ts
    │   ├── logger
    │   │   └── logger.ts
    │   ├── mail
    │   │   ├── mailerConfirmation.ts
    │   │   └── mailerRecovery.ts
    │   └── security
    │       └── rateLimit.ts
    ├── interfaces
    │   ├── controllers
    │   │   ├── auth
    │   │   │   ├── auth.controller.ts
    │   │   │   ├── confirm.controller.ts
    │   │   │   └── recover.controller.ts
    │   │   └── dashboard
    │   │       └── dashboard.controller.ts
    │   ├── middlewares
    │   │   ├── auth
    │   │   │   └── auth.middleware.ts
    │   │   ├── error
    │   │   │   ├── errorHandler.middleware.ts
    │   │   │   └── notFound.middleware.ts
    │   │   ├── role
    │   │   │   └── role.middleware.ts
    │   │   ├── sanitize
    │   │   │   └── sanitizeRequest.ts
    │   │   └── validate
    │   │       └── validateInput.ts
    │   └── routes
    │       ├── auth
    │       │   └── auth.routes.ts
    │       └── dashboard
    │           └── dashboard.routes.ts
    ├── shared
    │   ├── hash.ts
    │   ├── sanitize.ts
    │   ├── security
    │   │   └── jwt.ts
    │   ├── tokens.ts
    │   └── validations
    │       ├── auth.schema.ts
    │       └── validators.ts
    └── types
        └── express.d.ts
```