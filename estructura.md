# Estructura del Proyecto

```
├── backend
│   ├── coverage
│   │   └── lcov-report
│   │       ├── config
│   │       ├── constants
│   │       ├── repositories
│   │       ├── services
│   │       └── utils
│   ├── dist
│   │   ├── config
│   │   ├── constants
│   │   ├── controllers
│   │   ├── middlewares
│   │   ├── models
│   │   ├── repositories
│   │   ├── routes
│   │   ├── services
│   │   └── utils
│   │       └── __tests__
│   ├── logs
│   │   └── app.log
│   └── src
│       ├── app.ts
│       ├── config
│       │   ├── db.ts
│       │   ├── jwt.ts
│       │   ├── mailer.ts
│       │   └── rateLimit.ts
│       ├── constants
│       ├── controllers
│       │   ├── auth
│       │   │   └── auth.controller.ts
│       │   ├── confirm
│       │   │   └── confirm.controller.ts
│       │   ├── dashboard
│       │   │   └── dashboard.controller.ts
│       │   └── recover
│       │       └── recover.controller.ts
│       ├── index.ts
│       ├── middlewares
│       │   ├── auth
│       │   │   └── auth.middleware.ts
│       │   ├── error
│       │   │   ├── errorHandler.middleware.ts
│       │   │   └── notFound.middleware.ts
│       │   ├── role
│       │   │   └── role.middleware.ts
│       │   ├── sanitize
│       │   │   └── sanitizeRequest.ts
│       │   └── validate
│       │       └── validateInput.ts
│       ├── models
│       │   └── user
│       ├── repositories
│       │   └── user
│       │       └── user.repository.ts
│       ├── routes
│       │   ├── auth
│       │   │   └── auth.routes.ts
│       │   └── dashboard
│       │       └── dashboard.routes.ts
│       ├── services
│       │   ├── auth
│       │   │   └── auth.service.ts
│       │   ├── confirm
│       │   │   └── confirm.service.ts
│       │   ├── recovery
│       │   │   └── recovery.service.ts
│       │   └── user
│       ├── types
│       │   └── express
│       │       └── index.d.ts
│       ├── utils
│       │   ├── auth
│       │   ├── hash.ts
│       │   ├── logger.ts
│       │   ├── mailer
│       │   ├── mailerConfirmation.ts
│       │   ├── mailerRecovery.ts
│       │   ├── sanitize.ts
│       │   ├── tokens.ts
│       │   ├── validators.ts
│       │   └── __tests__
│       └── validations
│           ├── auth
│           ├── auth.schema.ts
│           └── user
└── frontend
    ├── contenido_archivos.md
    ├── eslint.config.js
    ├── index.html
    ├── public
    │   ├── ARP logo.png
    │   └── vite.svg
    ├── README.md
    ├── src
    │   ├── api
    │   │   └── axios.ts
    │   ├── App.css
    │   ├── App.tsx
    │   ├── assets
    │   │   └── react.svg
    │   ├── components
    │   │   ├── auth
    │   │   │   ├── AuthForm.tsx
    │   │   │   ├── AuthModal.tsx
    │   │   │   ├── AuthResendModal.tsx
    │   │   │   └── AuthSidePanel.tsx
    │   │   ├── common
    │   │   │   ├── Alert.tsx
    │   │   │   ├── Avatar.tsx
    │   │   │   ├── Breadcrumb.tsx
    │   │   │   ├── Button.tsx
    │   │   │   ├── Card.tsx
    │   │   │   ├── CardGrid.tsx
    │   │   │   ├── CustomToast.tsx
    │   │   │   ├── DropdownMenu.tsx
    │   │   │   ├── FormField.tsx
    │   │   │   ├── Input.tsx
    │   │   │   ├── InputWithLabel.tsx
    │   │   │   ├── Modal.tsx
    │   │   │   ├── PasswordField.tsx
    │   │   │   ├── PasswordWithStrengthInputForm.tsx
    │   │   │   ├── Spinner.tsx
    │   │   │   └── ToastNotification.tsx
    │   │   ├── NavMenu.tsx
    │   │   ├── RouteModalHandler.tsx
    │   │   └── ThemeToggle.tsx
    │   ├── context
    │   │   ├── AuthContext.tsx
    │   │   ├── ThemeContext.tsx
    │   │   └── ThemeProvider.tsx
    │   ├── hooks
    │   │   ├── useAuth.ts
    │   │   └── useTheme.ts
    │   ├── index.css
    │   ├── layout
    │   │   ├── Container.tsx
    │   │   ├── DashboardLayout.tsx
    │   │   ├── navigation
    │   │   │   ├── Footer.tsx
    │   │   │   ├── Header.tsx
    │   │   │   ├── HeaderMobile.tsx
    │   │   │   ├── MiniFooter.tsx
    │   │   │   └── Sidebar.tsx
    │   │   └── PublicLayout.tsx
    │   ├── main.tsx
    │   ├── pages
    │   │   ├── ConfirmAccount.tsx
    │   │   ├── ConfirmationMail.tsx
    │   │   ├── Dashboard.tsx
    │   │   ├── Home.tsx
    │   │   ├── Login.tsx
    │   │   ├── NotFound.tsx
    │   │   ├── Register.tsx
    │   │   └── ResetPassword.tsx
    │   ├── router
    │   │   └── AppRouter.tsx
    │   ├── store
    │   │   └── useAuthModal.ts
    │   ├── utils
    │   │   ├── auth.ts
    │   │   ├── PrivateRoute.tsx
    │   │   └── validationHelpersForm.ts
    │   └── vite-env.d.ts
    ├── tsconfig.app.json
    ├── tsconfig.node.json
    └── vite.config.ts
```