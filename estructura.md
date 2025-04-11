# Estructura del Proyecto

```
├── backend
│   ├── jest.config.ts
│   ├── package-lock.json
│   ├── package.json
│   ├── src
│   │   ├── app.ts
│   │   ├── config
│   │   │   ├── db.ts
│   │   │   ├── jwt.ts
│   │   │   └── mailer.ts
│   │   ├── controllers
│   │   │   ├── admin.controller.ts
│   │   │   ├── auth.controller.ts
│   │   │   ├── cart.controller.ts
│   │   │   ├── cart_items.controller.ts
│   │   │   ├── confirm.controller.ts
│   │   │   ├── dashboard.controller.ts
│   │   │   ├── emailLog.controller.ts
│   │   │   ├── freePass.controller.ts
│   │   │   ├── invoice.controller.ts
│   │   │   ├── permission.controller.ts
│   │   │   ├── qrScan.controller.ts
│   │   │   ├── resendConfirmation.controller.ts
│   │   │   ├── role.controller.ts
│   │   │   ├── rolePermission.controller.ts
│   │   │   ├── service.controller.ts
│   │   │   ├── tokenStatus.controller.ts
│   │   │   ├── user.controller.ts
│   │   │   └── userPermissions.controller.ts
│   │   ├── index.ts
│   │   ├── middlewares
│   │   │   ├── auth.middleware.ts
│   │   │   ├── errorHandler.middleware.ts
│   │   │   ├── notFound.middleware.ts
│   │   │   ├── role.middleware.ts
│   │   │   └── validation.middleware.ts
│   │   ├── models
│   │   │   ├── cart.model.ts
│   │   │   ├── emailLog.model.ts
│   │   │   ├── freePass.model.ts
│   │   │   ├── index.ts
│   │   │   ├── invoice.model.ts
│   │   │   ├── permission.model.ts
│   │   │   ├── qrScan.model.ts
│   │   │   ├── role.model.ts
│   │   │   ├── service.model.ts
│   │   │   └── user.model.ts
│   │   ├── routes
│   │   │   ├── admin.routes.ts
│   │   │   ├── auth.routes.ts
│   │   │   ├── cart.routes.ts
│   │   │   ├── cart_items.routes.ts
│   │   │   ├── clients.routes.ts
│   │   │   ├── dashboard.routes.ts
│   │   │   ├── emailLog.routes.ts
│   │   │   ├── freePass.routes.ts
│   │   │   ├── index.ts
│   │   │   ├── invoices.routes.ts
│   │   │   ├── permission.routes.ts
│   │   │   ├── qrScan.routes.ts
│   │   │   ├── role.routes.ts
│   │   │   ├── rolePermissions.routes.ts
│   │   │   ├── services.routes.ts
│   │   │   ├── userPermissions.routes.ts
│   │   │   └── users.routes.ts
│   │   ├── types
│   │   │   └── express
│   │   │       └── index.d.ts
│   │   └── utils
│   │       └── mailerConfirmation.ts
│   └── tsconfig.json
├── frontend
│   ├── eslint.config.js
│   ├── index.html
│   ├── package-lock.json
│   ├── package.json
│   ├── public
│   │   ├── ARP logo.png
│   │   └── vite.svg
│   ├── README.md
│   ├── src
│   │   ├── api
│   │   │   └── axios.ts
│   │   ├── App.css
│   │   ├── App.tsx
│   │   ├── assets
│   │   │   └── react.svg
│   │   ├── auth
│   │   │   ├── ConfirmMessage.tsx
│   │   │   ├── LoginForm.tsx
│   │   │   ├── RegisterForm.tsx
│   │   │   └── ResendConfirmationForm.tsx
│   │   ├── components
│   │   │   ├── auth
│   │   │   │   ├── AuthForm.tsx
│   │   │   │   ├── AuthModal.tsx
│   │   │   │   ├── AuthResendModal.tsx
│   │   │   │   └── AuthSidePanel.tsx
│   │   │   ├── authModal.tsx
│   │   │   ├── common
│   │   │   │   ├── Alert.tsx
│   │   │   │   ├── Avatar.tsx
│   │   │   │   ├── Breadcrumb.tsx
│   │   │   │   ├── Button.tsx
│   │   │   │   ├── Card.tsx
│   │   │   │   ├── CardGrid.tsx
│   │   │   │   ├── DropdownMenu.tsx
│   │   │   │   ├── FormField.tsx
│   │   │   │   ├── Input.tsx
│   │   │   │   ├── Modal.tsx
│   │   │   │   ├── PasswordField.tsx
│   │   │   │   ├── Spinner.tsx
│   │   │   │   └── ToastNotification.tsx
│   │   │   ├── NavMenu.tsx
│   │   │   └── ThemeToggle.tsx
│   │   ├── context
│   │   │   ├── AuthContext.tsx
│   │   │   ├── ThemeContext.tsx
│   │   │   └── ThemeProvider.tsx
│   │   ├── hooks
│   │   │   ├── useAuth.ts
│   │   │   └── useTheme.ts
│   │   ├── index.css
│   │   ├── layout
│   │   │   ├── Container.tsx
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
│   │   │   ├── ConfirmationMail.tsx
│   │   │   ├── Dashboard.tsx
│   │   │   ├── Home.tsx
│   │   │   ├── Login.tsx
│   │   │   └── Register.tsx
│   │   ├── routes
│   │   │   └── AppRouter.tsx
│   │   ├── store
│   │   │   └── useAuthModal.ts
│   │   ├── utils
│   │   │   ├── auth.ts
│   │   │   ├── helpers.ts
│   │   │   └── PrivateRoute.tsx
│   │   └── vite-env.d.ts
│   ├── tsconfig.app.json
│   ├── tsconfig.json
│   ├── tsconfig.node.json
│   └── vite.config.ts
└── getFullProjectInfo.js
```