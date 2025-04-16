# Estructura del Proyecto

```
└── src
    ├── app.ts
    ├── config
    │   ├── db.ts
    │   ├── jwt.ts
    │   ├── mailer.ts
    │   └── rateLimit.ts
    ├── controllers
    │   ├── admin.controller.ts
    │   ├── auth.controller.ts
    │   ├── cart.controller.ts
    │   ├── cart_items.controller.ts
    │   ├── confirm.controller.ts
    │   ├── dashboard.controller.ts
    │   ├── emailLog.controller.ts
    │   ├── freePass.controller.ts
    │   ├── invoice.controller.ts
    │   ├── permission.controller.ts
    │   ├── qrScan.controller.ts
    │   ├── recover.controller.ts
    │   ├── role.controller.ts
    │   ├── rolePermission.controller.ts
    │   ├── service.controller.ts
    │   ├── user.controller.ts
    │   └── userPermissions.controller.ts
    ├── index.ts
    ├── middlewares
    │   ├── auth.middleware.ts
    │   ├── errorHandler.middleware.ts
    │   ├── limiter.ts
    │   ├── notFound.middleware.ts
    │   ├── role.middleware.ts
    │   ├── validateInput.ts
    │   └── validation.middleware.ts
    ├── models
    │   ├── cart.model.ts
    │   ├── emailLog.model.ts
    │   ├── freePass.model.ts
    │   ├── index.ts
    │   ├── invoice.model.ts
    │   ├── permission.model.ts
    │   ├── qrScan.model.ts
    │   ├── role.model.ts
    │   ├── service.model.ts
    │   └── user.model.ts
    ├── repositories
    │   └── user.repository.ts
    ├── routes
    │   ├── admin.routes.ts
    │   ├── auth.routes.ts
    │   ├── cart.routes.ts
    │   ├── cart_items.routes.ts
    │   ├── clients.routes.ts
    │   ├── dashboard.routes.ts
    │   ├── emailLog.routes.ts
    │   ├── freePass.routes.ts
    │   ├── index.ts
    │   ├── invoices.routes.ts
    │   ├── permission.routes.ts
    │   ├── qrScan.routes.ts
    │   ├── role.routes.ts
    │   ├── rolePermissions.routes.ts
    │   ├── services.routes.ts
    │   ├── userPermissions.routes.ts
    │   └── users.routes.ts
    ├── services
    │   ├── auth.service.ts
    │   ├── confirm.service.ts
    │   └── recovery.service.ts
    ├── types
    │   ├── express
    │   │   └── index.d.ts
    │   └── xss-clean.d.ts
    ├── utils
    │   ├── hash.ts
    │   ├── logger.ts
    │   ├── mailerConfirmation.ts
    │   ├── mailerRecovery.ts
    │   ├── tokens.ts
    │   └── validators.ts
    └── validations
        └── auth.schema.ts
```