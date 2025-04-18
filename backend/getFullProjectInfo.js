import { readdirSync, statSync, readFileSync, writeFileSync } from "fs";
import { join, relative, extname } from "path";

const excluded = [
  "node_modules",
  ".env",
  ".git",
  ".gitignore", "jest.config.ts", "package-lock.json", "package.json", "tsconfig.json", "getFullProjectInfo.js","create-folders.js",
];
const jsonStructure = {};
const fileContents = {};

let markdownStructure = "# Estructura del Proyecto\n\n```\n";
let markdownContent = "# Contenido de Archivos\n\n";

function walk(dir, prefix = "", jsonObj = jsonStructure) {
  const files = readdirSync(dir).filter(file => !excluded.includes(file));

  files.forEach((file, index) => {
    const filePath = join(dir, file);
    const relPath = relative(process.cwd(), filePath);
    const isDir = statSync(filePath).isDirectory();
    const isLast = index === files.length - 1;
    const branch = `${prefix}${isLast ? "└── " : "├── "}${file}`;

    markdownStructure += `${branch}\n`;

    if (isDir) {
      jsonObj[file] = {};
      walk(filePath, prefix + (isLast ? "    " : "│   "), jsonObj[file]);
    } else {
      jsonObj[file] = null;

      try {
        const content = readFileSync(filePath, "utf-8");
        fileContents[relPath] = content;

        markdownContent += `## ${relPath}\n\n`;
        markdownContent += "```" + getLanguageFromExtension(file) + "\n";
        markdownContent += `${content}\n`;
        markdownContent += "```\n\n";
      } catch (err) {
        markdownContent += `## ${relPath}\n\nNo se pudo leer el archivo.\n\n`;
      }
    }
  });
}

function getLanguageFromExtension(filename) {
  const ext = extname(filename).toLowerCase();
  switch (ext) {
    case ".js": return "javascript";
    case ".ts": return "typescript";
    case ".jsx": return "jsx";
    case ".tsx": return "tsx";
    case ".html": return "html";
    case ".css": return "css";
    case ".json": return "json";
    case ".md": return "markdown";
    case ".scss": return "scss";
    case ".env": return "dotenv";
    default: return "";
  }
}

walk(process.cwd());
markdownStructure += "```";

// Guardar estructura
writeFileSync("estructura.md", markdownStructure, "utf-8");
writeFileSync("estructura.json", JSON.stringify(jsonStructure, null, 2), "utf-8");

// Guardar contenidos
writeFileSync("contenido_archivos.md", markdownContent, "utf-8");
writeFileSync("contenido_archivos.json", JSON.stringify(fileContents, null, 2), "utf-8");

console.log("✅ Archivos generados: estructura.md, estructura.json, contenido_archivos.md, contenido_archivos.json");
