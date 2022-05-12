module.exports = {
  content: [
	"./public/*.ejs",
	"./public/common/*.ejs",
  "./public/resources/*.js"
  ],
  darkMode: 'class', // or 'media' or 'class'
  theme: {
    extend: {},
    colors: {
      vukky: "#00a8f3",
      vwhite: "#f8f7ff",
      vgray: "#494949"
    }
  },
  variants: {
    extend: {}
  },
  plugins: [],
}
