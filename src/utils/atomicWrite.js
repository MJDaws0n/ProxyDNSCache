const fs = require('fs');
const path = require('path');

function atomicWriteFileSync(filePath, data, options = 'utf8') {
  const dir = path.dirname(filePath);
  const base = path.basename(filePath);
  const tmp = path.join(dir, `.${base}.${process.pid}.${Date.now()}.tmp`);

  fs.mkdirSync(dir, { recursive: true });
  fs.writeFileSync(tmp, data, options);
  fs.renameSync(tmp, filePath);
}

module.exports = {
  atomicWriteFileSync,
};
