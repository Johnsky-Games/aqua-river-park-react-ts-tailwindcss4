# Estructura del Proyecto

```
├── .vscode
│   └── settings.json
├── backend
│   ├── contenido_archivos.json
│   ├── contenido_archivos.md
│   ├── estructura.json
│   ├── estructura.md
│   ├── keys
│   │   ├── private.key
│   │   └── public.key
│   ├── logs
│   │   └── app.log
│   └── src
│       ├── app.ts
│       ├── config
│       │   ├── db.ts
│       │   ├── jwtKeys.ts
│       │   └── mailer.ts
│       ├── domain
│       │   ├── models
│       │   │   ├── auth
│       │   │   └── user
│       │   │       ├── cart.model.ts
│       │   │       ├── cartItem.model.ts
│       │   │       ├── permission.model.ts
│       │   │       ├── role.model.ts
│       │   │       ├── service.model.ts
│       │   │       └── user.model.ts
│       │   ├── ports
│       │   │   ├── refreshToken.repository.ts
│       │   │   ├── role.repository.ts
│       │   │   └── user.repository.ts
│       │   └── services
│       │       └── auth
│       │           ├── auth.service.ts
│       │           ├── confirm.service.ts
│       │           └── recovery.service.ts
│       ├── index.ts
│       ├── infraestructure
│       │   ├── db
│       │   │   ├── refreshToken.repository.ts
│       │   │   ├── role.repository.ts
│       │   │   └── user.repository.ts
│       │   ├── logger
│       │   │   ├── errorHandler.ts
│       │   │   └── logger.ts
│       │   ├── mail
│       │   │   ├── mailerConfirmation.ts
│       │   │   ├── mailerRecovery.ts
│       │   │   └── mailService.ts
│       │   ├── metrics
│       │   │   ├── customMetrics.ts
│       │   │   ├── metrics.ts
│       │   │   └── requestDurationHistogram.ts
│       │   └── security
│       │       └── rateLimit.ts
│       ├── interfaces
│       │   ├── controllers
│       │   │   ├── auth
│       │   │   │   ├── auth.controller.ts
│       │   │   │   ├── confirm.controller.ts
│       │   │   │   └── recover.controller.ts
│       │   │   ├── dashboard
│       │   │   │   └── dashboard.controller.ts
│       │   │   ├── health
│       │   │   │   └── health.controller.ts
│       │   │   └── user.controller.ts
│       │   ├── middlewares
│       │   │   ├── auth
│       │   │   │   └── auth.middleware.ts
│       │   │   ├── error
│       │   │   │   ├── errorHandler.middleware.ts
│       │   │   │   └── notFound.middleware.ts
│       │   │   ├── role
│       │   │   │   └── role.middleware.ts
│       │   │   ├── sanitize
│       │   │   │   └── sanitizeRequest.ts
│       │   │   └── validate
│       │   │       └── validateInput.ts
│       │   └── routes
│       │       ├── auth
│       │       │   └── auth.routes.ts
│       │       ├── dashboard
│       │       │   └── dashboard.routes.ts
│       │       ├── health
│       │       │   ├── health.routes.ts
│       │       │   └── metrics.routes.ts
│       │       ├── metrics
│       │       │   └── metrics.routes.ts
│       │       └── user.routes.ts
│       ├── shared
│       │   ├── errors
│       │   │   ├── createError.ts
│       │   │   ├── errorCodes.ts
│       │   │   └── errorMessages.ts
│       │   ├── hash.ts
│       │   ├── sanitize.ts
│       │   ├── security
│       │   │   └── jwt.ts
│       │   ├── succes
│       │   │   └── successMessages.ts
│       │   ├── tokens.ts
│       │   └── validations
│       │       ├── auth.schema.ts
│       │       └── validators.ts
│       ├── types
│       │   └── express.d.ts
│       └── utils
├── frontend
│   ├── contenido_archivos.json
│   ├── contenido_archivos.md
│   ├── eslint.config.js
│   ├── estructura.json
│   ├── estructura.md
│   ├── index.html
│   ├── public
│   │   ├── ARP logo.png
│   │   └── hero-bg.jpg
│   ├── README.md
│   ├── src
│   │   ├── api
│   │   │   └── axios.ts
│   │   ├── App.css
│   │   ├── App.tsx
│   │   ├── assets
│   │   │   ├── hero-bg.jpg
│   │   │   └── react.svg
│   │   ├── auth
│   │   ├── components
│   │   │   ├── auth
│   │   │   │   ├── AuthForm.tsx
│   │   │   │   ├── AuthModal.tsx
│   │   │   │   ├── AuthResendModal.tsx
│   │   │   │   └── AuthSidePanel.tsx
│   │   │   ├── AutoTokenManager.tsx
│   │   │   ├── common
│   │   │   │   ├── Alert.tsx
│   │   │   │   ├── Avatar.tsx
│   │   │   │   ├── Breadcrumb.tsx
│   │   │   │   ├── Button.tsx
│   │   │   │   ├── Card.tsx
│   │   │   │   ├── CardGrid.tsx
│   │   │   │   ├── CustomToast.tsx
│   │   │   │   ├── DropdownMenu.tsx
│   │   │   │   ├── FormField.tsx
│   │   │   │   ├── Input.tsx
│   │   │   │   ├── InputWithLabel.tsx
│   │   │   │   ├── Modal.tsx
│   │   │   │   ├── PasswordField.tsx
│   │   │   │   ├── PasswordWithStrengthInputForm.tsx
│   │   │   │   ├── Spinner.tsx
│   │   │   │   └── ToastNotification.tsx
│   │   │   ├── GlobalLoadingOverlay.tsx
│   │   │   ├── home
│   │   │   │   ├── Attractions.tsx
│   │   │   │   ├── Benefits.tsx
│   │   │   │   ├── Hero.tsx
│   │   │   │   ├── Location.tsx
│   │   │   │   └── RegisterInvoice.tsx
│   │   │   ├── LoginRedirectHandler.tsx
│   │   │   ├── NavMenu.tsx
│   │   │   ├── RouteModalHandler.tsx
│   │   │   ├── StatCard.tsx
│   │   │   ├── ThemeToggle.tsx
│   │   │   └── UserInitializer.tsx
│   │   ├── config
│   │   ├── context
│   │   │   ├── AuthContext.tsx
│   │   │   ├── ThemeContext.tsx
│   │   │   └── ThemeProvider.tsx
│   │   ├── hooks
│   │   │   └── useTheme.ts
│   │   ├── index.css
│   │   ├── layout
│   │   │   ├── DashboardLayout.tsx
│   │   │   ├── navigation
│   │   │   │   ├── Footer.tsx
│   │   │   │   ├── Header.tsx
│   │   │   │   ├── HeaderMobile.tsx
│   │   │   │   ├── MiniFooter.tsx
│   │   │   │   └── Sidebar.tsx
│   │   │   └── PublicLayout.tsx
│   │   ├── main.tsx
│   │   ├── pages
│   │   │   ├── admin
│   │   │   │   ├── DashboardView.tsx
│   │   │   │   ├── EntriesView.tsx
│   │   │   │   ├── InvoicesView.tsx
│   │   │   │   ├── SettingsView.tsx
│   │   │   │   └── UsersView.tsx
│   │   │   ├── ConfirmationMail.tsx
│   │   │   ├── Home.tsx
│   │   │   ├── NotFound.tsx
│   │   │   └── ResetPassword.tsx
│   │   ├── router
│   │   │   ├── AppRouter.tsx
│   │   │   └── PrivateRoute.tsx
│   │   ├── services
│   │   ├── store
│   │   │   ├── useAuthModal.ts
│   │   │   ├── useAuthStore.ts
│   │   │   └── useGlobalLoading.ts
│   │   ├── types
│   │   │   └── simple-parallax-js.d.ts
│   │   ├── utils
│   │   │   └── validationHelpersForm.ts
│   │   └── vite-env.d.ts
│   ├── tsconfig.app.json
│   ├── tsconfig.node.json
│   └── vite.config.ts
└── monitoring
    ├── docker-compose.yml
    └── prometheus.yml
```