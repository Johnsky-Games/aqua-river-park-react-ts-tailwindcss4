# Estructura del Proyecto

```
├── keys
│   ├── private.key
│   └── public.key
├── logs
└── src
    ├── app.ts
    ├── config
    │   ├── db.ts
    │   ├── jwtKeys.ts
    │   └── mailer.ts
    ├── domain
    │   ├── models
    │   │   ├── auth
    │   │   └── user
    │   │       ├── cart.model.ts
    │   │       ├── cartItem.model.ts
    │   │       ├── permission.model.ts
    │   │       ├── role.model.ts
    │   │       ├── service.model.ts
    │   │       └── user.model.ts
    │   ├── ports
    │   │   ├── refreshToken.repository.ts
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
    │   │   ├── refreshToken.repository.ts
    │   │   ├── role.repository.ts
    │   │   └── user.repository.ts
    │   ├── logger
    │   │   ├── errorHandler.ts
    │   │   └── logger.ts
    │   ├── mail
    │   │   ├── mailerConfirmation.ts
    │   │   ├── mailerRecovery.ts
    │   │   └── mailService.ts
    │   ├── metrics
    │   │   ├── customMetrics.ts
    │   │   ├── metrics.ts
    │   │   └── requestDurationHistogram.ts
    │   └── security
    │       └── rateLimit.ts
    ├── interfaces
    │   ├── controllers
    │   │   ├── auth
    │   │   │   ├── auth.controller.ts
    │   │   │   ├── confirm.controller.ts
    │   │   │   └── recover.controller.ts
    │   │   ├── dashboard
    │   │   │   └── dashboard.controller.ts
    │   │   ├── health
    │   │   │   └── health.controller.ts
    │   │   └── user.controller.ts
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
    │       ├── dashboard
    │       │   └── dashboard.routes.ts
    │       ├── health
    │       │   ├── health.routes.ts
    │       │   └── metrics.routes.ts
    │       ├── metrics
    │       │   └── metrics.routes.ts
    │       └── user.routes.ts
    ├── shared
    │   ├── errors
    │   │   ├── createError.ts
    │   │   ├── errorCodes.ts
    │   │   └── errorMessages.ts
    │   ├── hash.ts
    │   ├── sanitize.ts
    │   ├── security
    │   │   └── jwt.ts
    │   ├── succes
    │   │   └── successMessages.ts
    │   ├── tokens.ts
    │   └── validations
    │       ├── auth.schema.ts
    │       └── validators.ts
    ├── types
    │   └── express.d.ts
    └── utils
```