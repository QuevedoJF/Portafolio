# Product

<!-- impeccable:product-schema 1 -->

## Platform

web

## Users

Dos audiencias con el mismo peso (confirmado por el dueño):

- **Clientes freelance:** negocios o personas que necesitan un sitio web (cafeterías, consultorios, restaurantes, eventos) y están decidiendo a quién contratar. Quieren ver trabajos parecidos al suyo y una forma fácil de contactar.
- **Reclutadores y empresas:** evalúan a un estudiante a punto de egresar para un empleo o prácticas. Buscan evidencia de trabajo real, formación y participación más allá del aula.

El dueño, José Francisco Quevedo Hernández, es el único usuario del panel de administración (`admin.html`). Desde ahí edita el contenido sin tocar código.

## Product Purpose

Es el portafolio personal de un desarrollador web. Sirve para conseguir clientes freelance y oportunidades de empleo. Muestra proyectos publicados, tecnologías, eventos, certificaciones y un formulario de contacto.

Hay éxito cuando la visita termina en contacto: un mensaje desde el formulario, un correo o un mensaje por Instagram. También cuenta que un reclutador entienda en segundos quién es y qué ha hecho.

## Positioning

- **Sitios simples y rápidos:** "No uso frameworks de más ni complico las cosas sin necesidad". La promesa es que los sitios funcionen bien y se vean bien, sin complejidad innecesaria.
- **Experiencia real en eventos:** dos hackathons (2025 y 2026), el equipo NextCode en Open Tec 2026 y apoyo técnico en cursos y brigadas como servicio social. Es experiencia práctica comprobable, no solo cursos.

## Operating Context

- **Situación:** estudiante a punto de egresar. Las fechas de eventos y certificaciones son de 2025–2026.
- **Idioma:** todo el contenido está en español de México (`es-MX`).
- **Cómo llegan las visitas:** por el enlace compartido en WhatsApp, Instagram o LinkedIn (hay vista previa Open Graph) y por búsqueda en Google (el sitio público es indexable).
- **Cómo edita el dueño:** entra al admin con 5 clics rápidos en el logo. Los cambios se guardan automáticamente en la nube y hay historial de versiones.
- **Dominio de producción:** https://portafolio-jade-eight-28.vercel.app

## Capabilities and Constraints

- **Secciones públicas:** perfil (hero y "Acerca de mí"), tecnologías, proyectos (los 3 primeros visibles y "Ver más"), eventos, certificaciones con visor ampliado, y contacto (formulario, correo e Instagram).
- **Control de visibilidad:** en el admin, cada tarjeta y cada foto se puede ocultar sin borrarla. El correo, Instagram y la foto de perfil también se pueden mostrar u ocultar.
- **Stack existente:** HTML y CSS estáticos con JavaScript sin framework, desplegados en Vercel (funciones en `api/` y datos en Vercel Blob). No hay paso de build en Vercel.
  - El código fuente está en `app.src.js` y `admin.src.js` (ignorados por git). Lo que se publica son los `.min.js` ofuscados, que se regeneran con `npm run obfuscate`.
- **Seguridad:** la contraseña del admin vive en las variables de entorno de Vercel. El servidor filtra el contenido oculto antes de enviarlo al sitio público.
- **Robots:** se bloquea a los rastreadores de IA y no a los buscadores.
- **Sin decidir:** si se agregarán tarifas o paquetes de servicios para clientes freelance, y si habrá un CV descargable para reclutadores.

## Brand Commitments

- **Nombre público:** "José Francisco Quevedo Hernández". La marca corta es "Quevedo Hernández", con monograma "QH".
- **Rol:** "Desarrollador Web".
- **Voz:** primera persona, directa, cercana y sin tecnicismos de más. Por ejemplo: "Si necesitas un sitio web, una app o mejorar lo que ya tienes, contáctame y vemos cómo ayudarte."

## Evidence on Hand

- **Proyectos:**
  - Con capturas en `img/`: Página Cafetería, Página Eventos, Página Dentista, Página de Hamburguesas y Página Noticias.
  - Ocultos por ahora: Página Tec y Registro Tienda.
  - Varios tienen sitio en vivo en `*.vercel.app`.
- **Eventos (fotos en `img/eventos/`):**
  - Open Tec 2026 con el equipo NextCode.
  - Brigada Plantel 28.
  - Apoyo técnico en cursos para la Universidad Tecnológica del Istmo y para estudiantes del Tec y de prepa en Villahermosa (servicio social).
- **Certificaciones (en `img/cursos/`):**
  - Hackathon 2025 y Hackathon 2026.
  - Cursos de Capacítate para el Empleo (Fundación Carlos Slim): Técnico en Seguridad, Técnico en Seguridad Perimetral, Técnico en Redes IP, Fundamentos de Seguridad y Administrador de Servidores.
- **Foto de perfil:** `img/Perfil/foto.jpeg`.
- **Lo que NO existe** y no debe inventarse:
  - testimonios o reseñas de clientes,
  - nombres de clientes reales más allá de los títulos de proyecto,
  - precios,
  - métricas de resultados (visitas, ventas),
  - empleos formales previos.

## Product Principles

1. **La evidencia antes que las promesas:** proyectos en vivo, fotos de eventos y certificados reales pesan más que cualquier adjetivo.
2. **Servir a las dos audiencias sin duplicar:** el cliente ve trabajos para negocios como el suyo y el reclutador ve formación y participación, en el mismo recorrido.
3. **Simple y rápido, como lo que vende:** el portafolio debe cumplir la promesa de sitios ligeros y claros que funcionan bien.
4. **El contacto siempre a la mano:** cualquier visita debe poder escribir sin buscar.
5. **El dueño edita sin código y sin riesgo:** los cambios del admin se guardan de forma confiable y son reversibles.
