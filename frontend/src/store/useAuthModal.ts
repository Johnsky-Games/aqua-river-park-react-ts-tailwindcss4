import { create } from "zustand";

interface AuthModalState {
  isOpen: boolean;
  view: "login" | "register";
  openModal: (view?: "login" | "register") => void;
  closeModal: () => void;
  toggleView: () => void;
}

export const useAuthModal = create<AuthModalState>((set) => ({
  isOpen: false,
  view: "login",
  openModal: (view = "login") => set({ isOpen: true, view }),
  closeModal: () => set({ isOpen: false }),
  toggleView: () =>
    set((state) => ({
      view: state.view === "login" ? "register" : "login",
    })),
}));
