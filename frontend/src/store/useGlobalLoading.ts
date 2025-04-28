import { create } from "zustand";

interface GlobalLoadingState {
  isLoading: boolean;
  setLoading: (loading: boolean) => void;
}

export const useGlobalLoading = create<GlobalLoadingState>((set) => ({
  isLoading: false,
  setLoading: (loading) => set({ isLoading: loading }),
}));
