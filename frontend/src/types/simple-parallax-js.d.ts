declare module "simple-parallax-js" {
  interface SimpleParallaxOptions {
    scale?: number;
    delay?: number;
    transition?: string;
    orientation?: "up" | "down" | "left" | "right";
  }

  export default function simpleParallax(
    el: Element | Element[] | NodeListOf<Element>,
    options?: SimpleParallaxOptions
  ): void;
}
