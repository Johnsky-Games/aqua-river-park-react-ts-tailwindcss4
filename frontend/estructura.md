# Estructura del Proyecto

```
├── eslint.config.js
├── index.html
├── public
│   ├── ARP logo.png
│   └── hero-bg.jpg
├── README.md
├── src
│   ├── api
│   │   └── axios.ts
│   ├── App.css
│   ├── App.tsx
│   ├── assets
│   │   ├── hero-bg.jpg
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
│   │   ├── home
│   │   │   ├── Attractions.tsx
│   │   │   ├── Benefits.tsx
│   │   │   ├── Hero.tsx
│   │   │   ├── Location.tsx
│   │   │   └── RegisterInvoice.tsx
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
│   ├── types
│   │   └── simple-parallax-js.d.ts
│   ├── utils
│   │   ├── PrivateRoute.tsx
│   │   └── validationHelpersForm.ts
│   └── vite-env.d.ts
├── tsconfig.app.json
├── tsconfig.node.json
└── vite.config.ts
```