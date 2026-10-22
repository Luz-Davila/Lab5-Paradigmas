// Libreria de validacion y saneamiento de mensajes para UNA Chat.
// Todas las funciones son puras para poder probarlas con Mocha (BDD).
//
// Regla de oro: nada que venga del cliente se inserta en el DOM sin
// validarse (URLs) o escaparse (texto libre).

var MAX_LONGITUD_MENSAJE = 2000;
var MAX_LONGITUD_NOMBRE = 50;
var MAX_LONGITUD_URL = 2048;

var NOMBRE_POR_DEFECTO = 'Anónimo';
var COLOR_POR_DEFECTO = '#000000';

var RE_COLOR_HEX = /^#[0-9A-Fa-f]{6}$/;
var RE_EXTENSION_IMAGEN = /\.(png|jpe?g|gif|webp|bmp)$/i;
var RE_EXTENSION_VIDEO = /\.(mp4|webm|ogv|ogg|mov)$/i;
var RE_ID_YOUTUBE = /^[A-Za-z0-9_-]{11}$/;
var RE_PROTOCOLO_HTTP = /^https?:\/\//i;

// Se rechazan espacios, comillas, parentesis angulares, backticks y
// backslashes: nunca son necesarios en una URL legitima y son el vehiculo
// clasico para romper un atributo HTML e inyectar codigo.
var RE_CARACTERES_PELIGROSOS = /[<>"'`\\\s]/;

function recortar(texto, maximo) {
  if (typeof texto !== 'string') {
    return '';
  }
  return texto.length > maximo ? texto.slice(0, maximo) : texto;
}

// Convierte texto libre en texto seguro para insertarlo como HTML.
// El orden importa: el ampersand debe escaparse primero.
function escapeHtml(valor) {
  if (valor === null || valor === undefined) {
    return '';
  }

  return String(valor)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;')
    .replace(/`/g, '&#96;');
}

// Devuelve un objeto URL ya normalizado o null si no es una URL
// http/https confiable.
function analizarUrl(url) {
  if (typeof url !== 'string') {
    return null;
  }

  var limpia = url.trim();

  if (limpia === '' || limpia.length > MAX_LONGITUD_URL) {
    return null;
  }

  if (!RE_PROTOCOLO_HTTP.test(limpia) || RE_CARACTERES_PELIGROSOS.test(limpia)) {
    return null;
  }

  try {
    var parsed = new URL(limpia);

    if (parsed.protocol !== 'http:' && parsed.protocol !== 'https:') {
      return null;
    }

    return parsed;
  } catch (e) {
    return null;
  }
}

function is_valid_url_image(url) {
  var parsed = analizarUrl(url);
  return parsed !== null && RE_EXTENSION_IMAGEN.test(parsed.pathname);
}

function is_valid_video_url(url) {
  var parsed = analizarUrl(url);
  return parsed !== null && RE_EXTENSION_VIDEO.test(parsed.pathname);
}

// Extrae el id (11 caracteres) de un enlace de YouTube o null si no lo es.
// Se valida el host y el id por separado para no depender de una unica
// expresion regular fragil.
function getYTVideoId(url) {
  var parsed = analizarUrl(url);

  if (!parsed) {
    return null;
  }

  var host = parsed.hostname.toLowerCase().replace(/^www\./, '');
  var id = null;

  if (host === 'youtu.be') {
    id = parsed.pathname.split('/')[1];
  } else if (host === 'youtube.com' || host === 'm.youtube.com') {
    if (parsed.pathname === '/watch') {
      id = parsed.searchParams.get('v');
    } else {
      var partes = parsed.pathname.split('/').filter(function (parte) { return parte !== ''; });
      var prefijo = partes[0];

      if (partes.length >= 2 && (prefijo === 'embed' || prefijo === 'v' || prefijo === 'shorts')) {
        id = partes[1];
      }
    }
  }

  return id && RE_ID_YOUTUBE.test(id) ? id : null;
}

function is_valid_yt_video(url) {
  return getYTVideoId(url) !== null;
}

function getImageTag(url) {
  var parsed = analizarUrl(url);

  if (!parsed || !RE_EXTENSION_IMAGEN.test(parsed.pathname)) {
    return '';
  }

  return '<img src="' + escapeHtml(parsed.href) + '" alt="Imagen compartida" ' +
    'loading="lazy" referrerpolicy="no-referrer" ' +
    'style="max-height: 400px; max-width: 400px;">';
}

function getVideoTag(url) {
  var parsed = analizarUrl(url);

  if (!parsed || !RE_EXTENSION_VIDEO.test(parsed.pathname)) {
    return '';
  }

  return '<video controls preload="metadata" src="' + escapeHtml(parsed.href) + '" ' +
    'style="max-height: 400px; max-width: 400px;"></video>';
}

function getEmbeddedCode(url) {
  var id = getYTVideoId(url);

  if (!id) {
    return '';
  }

  // El id ya fue validado con RE_ID_YOUTUBE, por lo que solo puede contener
  // letras, numeros, guion y guion bajo.
  return '<iframe width="560" height="315" src="https://www.youtube.com/embed/' + id + '" ' +
    'frameborder="0" allow="accelerometer; autoplay; encrypted-media; gyroscope; picture-in-picture" ' +
    'allowfullscreen></iframe>';
}

function respuestaBase() {
  return {
    nombre: NOMBRE_POR_DEFECTO,
    color: COLOR_POR_DEFECTO,
    mensaje: '',
    tipo: 'texto',
    url: '',
    videoId: ''
  };
}

// Punto unico de entrada del servidor: recibe el JSON crudo del cliente y
// devuelve un JSON con todos los campos saneados.
function validateMessage(msg) {
  var resultado = respuestaBase();

  if (typeof msg !== 'string' || msg.trim() === '') {
    return JSON.stringify(resultado);
  }

  var crudo = recortar(msg.trim(), MAX_LONGITUD_MENSAJE);
  var obj;

  try {
    obj = JSON.parse(crudo);
  } catch (e) {
    // Un mensaje que no es JSON se trata como texto plano y se escapa.
    resultado.mensaje = escapeHtml(crudo);
    return JSON.stringify(resultado);
  }

  if (typeof obj === 'string') {
    resultado.mensaje = escapeHtml(recortar(obj.trim(), MAX_LONGITUD_MENSAJE));
    return JSON.stringify(resultado);
  }

  if (!obj || typeof obj !== 'object' || Array.isArray(obj)) {
    return JSON.stringify(resultado);
  }

  var nombre = typeof obj.nombre === 'string' ? recortar(obj.nombre.trim(), MAX_LONGITUD_NOMBRE) : '';
  resultado.nombre = escapeHtml(nombre || NOMBRE_POR_DEFECTO);

  // Solo se acepta un color en formato #RRGGBB. Cualquier intento de colar
  // CSS o JavaScript por el atributo style cae al color por defecto.
  resultado.color = typeof obj.color === 'string' && RE_COLOR_HEX.test(obj.color)
    ? obj.color
    : COLOR_POR_DEFECTO;

  var contenido = typeof obj.mensaje === 'string'
    ? recortar(obj.mensaje.trim(), MAX_LONGITUD_MENSAJE)
    : '';

  if (contenido === '') {
    return JSON.stringify(resultado);
  }

  if (is_valid_url_image(contenido)) {
    var imagen = analizarUrl(contenido);
    resultado.tipo = 'imagen';
    resultado.url = imagen.href;
    resultado.mensaje = getImageTag(imagen.href);
    return JSON.stringify(resultado);
  }

  if (is_valid_yt_video(contenido)) {
    var video = analizarUrl(contenido);
    resultado.tipo = 'video_youtube';
    resultado.url = video.href;
    resultado.videoId = getYTVideoId(contenido);
    resultado.mensaje = getEmbeddedCode(contenido);
    return JSON.stringify(resultado);
  }

  if (is_valid_video_url(contenido)) {
    var archivo = analizarUrl(contenido);
    resultado.tipo = 'video';
    resultado.url = archivo.href;
    resultado.mensaje = getVideoTag(archivo.href);
    return JSON.stringify(resultado);
  }

  // Todo lo demas es texto: se escapa y jamas se interpreta como HTML.
  resultado.mensaje = escapeHtml(contenido);
  return JSON.stringify(resultado);
}

module.exports = {
  MAX_LONGITUD_MENSAJE: MAX_LONGITUD_MENSAJE,
  MAX_LONGITUD_NOMBRE: MAX_LONGITUD_NOMBRE,
  COLOR_POR_DEFECTO: COLOR_POR_DEFECTO,
  escapeHtml: escapeHtml,
  is_valid_phone: function (phone) {
    // inicializacion lazy
    var isValid = false;
    // expresion regular copiada de StackOverflow
    var re = /^[+]*[(]{0,1}[0-9]{1,4}[)]{0,1}[-\s\./0-9]*$/i;

    // validacion Regex
    try {
      isValid = re.test(phone);
    } catch (e) {
      console.log(e);
    } finally {
      return isValid;
    }
  },
  is_valid_url_image: is_valid_url_image,
  is_valid_video_url: is_valid_video_url,
  is_valid_yt_video: is_valid_yt_video,
  getYTVideoId: getYTVideoId,
  getEmbeddedCode: getEmbeddedCode,
  getImageTag: getImageTag,
  getVideoTag: getVideoTag,
  validateMessage: validateMessage
};
