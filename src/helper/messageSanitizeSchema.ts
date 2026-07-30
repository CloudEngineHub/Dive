import { defaultSchema } from "rehype-sanitize"

// Sanitize schema for markdown that is rendered with `rehypeRaw` (raw HTML passthrough).
// Assistant messages and marketplace server descriptions are untrusted, so raw HTML in them
// must be scrubbed of script-bearing elements/attributes (iframe/script/object/embed/form,
// srcDoc, on* handlers, javascript: URLs) while still permitting the app's own custom render
// tags and KaTeX output.
//
// IMPORTANT: apply this AFTER rehypeRaw but BEFORE rehypeKatex. KaTeX emits its own MathML +
// styled spans from a trusted library; running sanitize before it keeps the `math-inline` /
// `math-display` marker spans intact for KaTeX to render, and leaves KaTeX's trusted output
// untouched. `src` on media is still an `https://localfile…` URL at this stage (the
// `local-file://` conversion happens later inside the React components), so the default
// http/https protocol allow-list does not break local media.
const defaults = defaultSchema
const globalAttrs = (defaults.attributes && defaults.attributes["*"]) || []

export const messageSanitizeSchema = {
  ...defaults,
  // Don't rewrite `name`/`id` with the `user-content-` clobber prefix: the app's custom tags
  // (tool-call, system-tool-call) read `name` as a functional prop, and the DOM-clobbering
  // sinks that prefix guards against (form/input/iframe/etc.) are already removed by the
  // tagName allow-list below.
  clobber: [],
  tagNames: [
    ...(defaults.tagNames || []),
    // app-defined custom render tags (see components map in Message.tsx)
    "think",
    "none",
    "chat-error",
    "thread-query-error",
    "rate-limit-exceeded",
    "tool-call",
    "system-tool-call",
    // media tags react-markdown renders via custom components
    "video",
    "audio",
  ],
  attributes: {
    ...defaults.attributes,
    // className is needed for KaTeX marker spans, code language classes, and the app's own tags
    "*": [...globalAttrs, "className"],
    "tool-call": ["name", "toolkey", "messageid"],
    "system-tool-call": ["name"],
    video: ["src", "controls", "className"],
    audio: ["src", "controls", "className"],
  },
}
