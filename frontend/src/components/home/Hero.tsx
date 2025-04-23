import { useEffect, useRef } from "react";
import { Parallax } from "react-scroll-parallax";
import { createTimeline } from "animejs";

export const Hero = () => {
  const titleRef = useRef<HTMLHeadingElement>(null);
  const subtitleRef = useRef<HTMLParagraphElement>(null);
  const buttonRef = useRef<HTMLAnchorElement>(null);

  useEffect(() => {
    if (!titleRef.current || !subtitleRef.current || !buttonRef.current) return;

    const tl = createTimeline();

    tl.add(titleRef.current, {
      opacity: [0, 1],
      translateY: [-50, 0],
      easing: "easeOutExpo",
      duration: 1000,
    })
      .add(
        subtitleRef.current,
        {
          opacity: [0, 1],
          translateY: [30, 0],
          easing: "easeOutExpo",
          duration: 800,
        },
        "-=500"
      )
      .add(
        buttonRef.current,
        {
          opacity: [0, 1],
          scale: [0.9, 1],
          easing: "easeOutBack",
          duration: 600,
        },
        "-=500"
      );
  }, []);

  return (
    <section
      id="hero"
      className="relative min-h-[90vh] flex items-center justify-center text-center px-6 overflow-hidden"
    >
      {/* Fondo con parallax y overlay oscuro */}
      <div className="absolute inset-0 z-0 pointer-events-none top-0">
        <Parallax speed={-100}>
          <img
            src="/hero-bg.jpg"
            alt="Fondo Aqua River Park"
            className="w-full h-full object-cover"
          />
          <div className="absolute inset-0 bg-bgDark/70 z-10" />
        </Parallax>
      </div>

      {/* Contenido */}
      <div className="relative z-20 max-w-4xl text-textLight">
        <h1
          ref={titleRef}
          className="text-4xl md:text-6xl font-bold leading-tight mb-6 opacity-0 drop-shadow-md"
        >
          Bienvenido a <span className="text-primary">Aqua River Park</span>
        </h1>
        <p
          ref={subtitleRef}
          className="text-lg md:text-xl mb-8 opacity-0 max-w-2xl mx-auto text-[--color-textLight]/90"
        >
          Diversión, naturaleza y experiencias inolvidables para toda la familia.
        </p>
        <a
          ref={buttonRef}
          href="#register"
          className="inline-block bg-accent2 text-white font-semibold px-8 py-3 rounded-full shadow-xl hover:bg-primary hover:text-white duration-300 opacity-0"
        >
          Registra tus facturas
        </a>
      </div>
    </section>
  );
};
