import fs from 'fs';
import { isAbsolute, resolve } from 'path';

const log = console.log;
const aliasSymbol = '#';

function parseArguments() {
  const args = process.argv.slice(2);
  const pathFlagIndex = args.indexOf('-p');
  const pathValue = pathFlagIndex !== -1 ? args[pathFlagIndex + 1] : '.';
  if (!pathValue) {
    console.error('Error: No path provided after -p. Exiting.');
    process.exit(1);
  }
  const clearComments = !(
    args.includes('-c') && args[args.indexOf('-c') + 1] === 'false'
  );
  return { pathValue, clearComments };
}

function getSourceDirectory(targetPath) {
  const invocationDir = process.cwd();
  return isAbsolute(targetPath)
    ? targetPath
    : resolve(invocationDir, targetPath);
}

function gatherJsFiles(dir, accumulated = []) {
  const entries = fs.readdirSync(dir);
  entries.forEach((entry) => {
    const fullPath = resolve(dir, entry);
    if (fs.statSync(fullPath).isDirectory())
      gatherJsFiles(fullPath, accumulated);
    else if (fullPath.endsWith('.js')) accumulated.push(fullPath);
  });
  return accumulated;
}

function extractDetails(text) {
  const imports = text.match(/import ([^;]|\r|\n|\r\n)*;{1}/gm) || [];
  const exportsRaw = text.match(/export [^ ]* [^ ]*/gm) || [];
  const exports = exportsRaw.map((exp) =>
    exp.split(' ')[2].replace(/\(.*/, '')
  );
  return { text, imports, exports };
}

function stripComments(text) {
  return text
    .replace(/(?<!\S)\/\/.*/g, '')
    .replace(/\/\*{1,2}[\s\S]*?\*\//g, '');
}

function removeAliasImports(fileDetails) {
  let { text } = fileDetails;
  fileDetails.imports.forEach((imp, i) => {
    if (imp.includes(' as ')) {
      imp
        .replace('import ', '')
        .replace(/from.*/, ' ')
        .replace(/{/g, '')
        .replace(/}/g, '')
        .replace(/\r\n/g, '')
        .split(',')
        .map((a) => a.trim())
        .map((u) => {
          if (u.includes(' as ')) {
            const [name, alias] = u.split(' as ');
            text = text.replace(` as ${alias}`, '');

            // cache oryginal from with the path
            const from = imp.match(/from .*;{1}/)[0];

            // replace all alias with the name, but avoid replacing inside other names
            text = text.replace(
              new RegExp(`(\\W)${alias}(\\W)`, 'g'),
              `$1${name}$2`
            );

            // in case alias would also be part of the path, put it back
            text = text.replace(
              new RegExp(`(?<= ${name} .*)from .*;{1}`, 'g'),
              from
            );

            fileDetails.imports[i] = fileDetails.imports[i].replace(
              `${name} as ${alias}`,
              name
            );
          }
        });
    }
  });
  fileDetails.text = text;
}

function sortByDependencies(files) {
  const noImports = [];
  const libraryImportsOnly = [];
  const customImports = [];
  let index;

  files.forEach((file) => {
    const { imports, exports } = file;
    if (exports.length === 0) {
      index = file;
      return;
    }
    if (imports.length === 0) {
      noImports.push(file);
      return;
    }
    const notCustom = imports.every(
      (i) => !i.includes('./') && !i.includes(aliasSymbol)
    );
    if (notCustom) {
      libraryImportsOnly.push(file);
      return;
    }

    customImports.push(file);
  });

  const sorted = [];
  while (customImports.length > 0) {
    const current = customImports.shift();
    const { imports } = current;
    const dependencies = customImports.reduce((acc, file) => {
      const { exports } = file;
      if (imports.some((i) => exports.includes(i))) {
        acc.push(file);
      }
      return acc;
    }, []);
    if (dependencies.length === 0) {
      sorted.push(current);
    } else {
      customImports.push(current);
    }
  }

  return [...noImports, ...libraryImportsOnly, ...sorted, index];
}

function removeRelativeAndAliasImports(fileDetails) {
  const cleanImports = [];
  fileDetails.imports.forEach((imp) => {
    if (imp.includes(aliasSymbol) || imp.includes('./'))
      fileDetails.text = fileDetails.text.replace(imp, '');
    else cleanImports.push(imp);
  });
  fileDetails.imports = cleanImports;
}

function getUniqueImports(files) {
  const allImports = files.flatMap((file) => file.imports);
  return Array.from(new Set(allImports));
}

function processFiles(files, clearComments) {
  let processedFiles = files.map((fileName) => {
    const raw = fs.readFileSync(fileName, 'utf8');
    const details = extractDetails(raw);
    removeAliasImports(details);
    return { name: fileName, ...details };
  });

  processedFiles = sortByDependencies(processedFiles);

  processedFiles = processedFiles.map((fileData) => {
    if (clearComments) fileData.text = stripComments(fileData.text);
    removeRelativeAndAliasImports(fileData);
    fileData.imports.forEach((imp) => {
      fileData.text = fileData.text.replace(imp, '');
    });
    return fileData;
  });

  return processedFiles;
}

function createCombinedText(data) {
  // return data.map(({ text }) => `\n${text}\n`).join('\n');
  return data.map(({ text, name }) => `// ${name}\n\n${text}\n`).join('\n');
}

function cleanupText(text) {
  return (
    text
      // replace all multiple new lines with single new line
      .replace(/\n{2,}/g, '\n')
      // replace all new lines followed by white spaces only with single new line
      .replace(/\n\s*\n/g, '\n')
      .replace(/export /g, '')
  );
}

(function main() {
  const { pathValue, clearComments } = parseArguments();
  const sourceDirectory = getSourceDirectory(pathValue);
  const outputFile = resolve(sourceDirectory, 'combined.js');
  if (fs.existsSync(outputFile)) fs.unlinkSync(outputFile);
  const files = gatherJsFiles(sourceDirectory);
  let allFilesData = processFiles(files, clearComments);
  const uniqueImports = getUniqueImports(allFilesData);
  uniqueImports.forEach((imp) => fs.appendFileSync(outputFile, `${imp}\n`));
  const sorted = sortByDependencies(allFilesData);
  const singleText = createCombinedText(sorted);
  fs.appendFileSync(outputFile, cleanupText(singleText));
  log('Done.');
})();
