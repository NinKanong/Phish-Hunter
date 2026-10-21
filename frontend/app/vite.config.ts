import {defineConfig} from 'vite';
import react from '@vitejs/plugin-react';
export default defineConfig({plugins:[react()],base:'/static/workbench/',build:{outDir:'../../phishhunter/web/static/workbench',emptyOutDir:true}});
