module.exports = {
  content: [
	"./public/*.ejs",
	"./public/common/*.ejs",
	"./public/oauth/*.ejs",
  "./public/resources/*.js"
  ],
  darkMode: 'class', // or 'media' or 'class'
  theme: {
    extend: {
      colors: {
        'vukky': "#00a8f3",
        'vwhite': "#f8f7ff",
        'vgray': "#494949",
        'wdark': '#3c3c45',
        'wlight': '#e0e0e0',
        'wlight-dark': '#555562',
        'wblue-dark': '#227baa'
      }
    },
  },
  variants: {
    extend: {}
  },
  plugins: [
    require('@tailwindcss/line-clamp'),
    require('tw-elements/dist/plugin')
  ],
}
