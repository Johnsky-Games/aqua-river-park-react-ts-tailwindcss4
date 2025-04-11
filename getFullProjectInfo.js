const fs = require("fs");
const path = require("path");

const excluded = ["node_modules", ".env", ".git", ".gitignore"];
const jsonStructure = {};
const fileContents = {};

let markdownStructure = "# Estructura del Proyecto\n\n```\n";
let markdownContent = "# Contenido de Archivos\n\n";

function walk(dir, prefix = "", jsonObj = jsonStructure) {
  const files = fs.readdirSync(dir).filter(file => !excluded.includes(file));
  
  files.forEach((file, index) => {
    const filePath = path.join(dir, file);
    const relPath = path.relative(process.cwd(), filePath);
    const isDir = fs.statSync(filePath).isDirectory();
    const isLast = index === files.length - 1;
    const branch = `${prefix}${isLast ? "└── " : "├── "}${file}`;
    
    markdownStructure += `${branch}\n`;

    if (isDir) {
      jsonObj[file] = {};
      walk(filePath, prefix + (isLast ? "    " : "│   "), jsonObj[file]);
    } else {
      jsonObj[file] = null;

      try {
        const content = fs.readFileSync(filePath, "utf-8");
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
  const ext = path.extname(filename).toLowerCase();
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
fs.writeFileSync("estructura.md", markdownStructure, "utf-8");
fs.writeFileSync("estructura.json", JSON.stringify(jsonStructure, null, 2), "utf-8");

// Guardar contenidos
fs.writeFileSync("contenido_archivos.md", markdownContent, "utf-8");
fs.writeFileSync("contenido_archivos.json", JSON.stringify(fileContents, null, 2), "utf-8");

console.log("✅ Archivos generados: estructura.md, estructura.json, contenido_archivos.md, contenido_archivos.json");
