import resolve from '@rollup/plugin-node-resolve';
import commonjs from '@rollup/plugin-commonjs';
import terser from '@rollup/plugin-terser';

export default [
  // ES Module build
  {
    input: 'src/index.js',
    output: {
      file: 'dist/index.esm.js',
      format: 'es'
    },
    plugins: [resolve(), commonjs()]
  },
  // CommonJS build
  {
    input: 'src/index.js',
    output: {
      file: 'dist/index.js',
      format: 'cjs',
      exports: 'named'
    },
    plugins: [resolve(), commonjs()]
  },
  // UMD build (for browsers)
  {
    input: 'src/index.js',
    output: {
      file: 'dist/form-gate.min.js',
      format: 'umd',
      name: 'FormGate'
    },
    plugins: [resolve(), commonjs(), terser()]
  }
];