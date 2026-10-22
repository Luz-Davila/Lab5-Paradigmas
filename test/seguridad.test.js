var assert = require('assert');
var fs = require('fs');
var path = require('path');
var val = require('../libs/unalib');

// Helper: validateMessage devuelve un string JSON, lo pasamos a objeto.
function validar(payload) {
  return JSON.parse(val.validateMessage(payload));
}

function mensajeJson(campos) {
  return JSON.stringify(campos);
}

describe('Seguridad del chat UNA', function () {

  describe('Saneamiento de HTML (escapeHtml)', function () {

    it('debería escapar los caracteres especiales de una etiqueta <script>', function () {
      var salida = val.escapeHtml('<script>alert("XSS")</script>');

      assert.equal(salida, '&lt;script&gt;alert(&quot;XSS&quot;)&lt;/script&gt;');
      assert.equal(salida.indexOf('<script'), -1);
    });

    it('debería escapar el ampersand antes que el resto de entidades', function () {
      assert.equal(val.escapeHtml('&lt;'), '&amp;lt;');
    });

    it('debería escapar comillas simples, dobles y backticks', function () {
      assert.equal(val.escapeHtml('\' " `'), '&#39; &quot; &#96;');
    });

    it('debería devolver una cadena vacía para null y undefined', function () {
      assert.equal(val.escapeHtml(null), '');
      assert.equal(val.escapeHtml(undefined), '');
    });

  });

  describe('Validación de URLs de imagen', function () {

    it('debería aceptar una URL http con extensión .jpg', function () {
      assert.equal(val.is_valid_url_image('http://image.com/image.jpg'), true);
    });

    it('debería aceptar una URL https con extensión .png', function () {
      assert.equal(val.is_valid_url_image('https://image.com/foto.png'), true);
    });

    it('debería aceptar una URL con parámetros de consulta', function () {
      assert.equal(val.is_valid_url_image('https://image.com/foto.jpg?w=100&h=100'), true);
    });

    it('debería aceptar la extensión sin importar mayúsculas', function () {
      assert.equal(val.is_valid_url_image('https://image.com/FOTO.JPG'), true);
    });

    it('debería rechazar un enlace de YouTube', function () {
      assert.equal(val.is_valid_url_image('https://www.youtube.com/watch?v=qYwlqx-JLok'), false);
    });

    it('debería rechazar una URL con protocolo javascript:', function () {
      assert.equal(val.is_valid_url_image('javascript:alert(1)'), false);
    });

    it('debería rechazar una URL con protocolo data:', function () {
      assert.equal(val.is_valid_url_image('data:image/png;base64,AAAA'), false);
    });

    it('debería rechazar una URL que esconde una etiqueta en el atributo', function () {
      assert.equal(val.is_valid_url_image('http://image.com/a.jpg" onerror="alert(1)'), false);
    });

  });

  describe('Validación de URLs de video', function () {

    it('debería aceptar un archivo .mp4', function () {
      assert.equal(val.is_valid_video_url('https://video.com/clip.mp4'), true);
    });

    it('debería aceptar un archivo .webm', function () {
      assert.equal(val.is_valid_video_url('https://video.com/clip.webm'), true);
    });

    it('debería rechazar una imagen', function () {
      assert.equal(val.is_valid_video_url('https://video.com/foto.jpg'), false);
    });

    it('debería rechazar una URL con protocolo javascript:', function () {
      assert.equal(val.is_valid_video_url('javascript:alert(1)'), false);
    });

  });

  describe('Validación de videos de YouTube', function () {

    it('debería aceptar un enlace watch?v=', function () {
      assert.equal(val.is_valid_yt_video('https://www.youtube.com/watch?v=qYwlqx-JLok'), true);
    });

    it('debería aceptar un enlace corto youtu.be', function () {
      assert.equal(val.is_valid_yt_video('https://youtu.be/qYwlqx-JLok'), true);
    });

    it('debería aceptar un enlace embed y extraer el id', function () {
      assert.equal(val.getYTVideoId('https://www.youtube.com/embed/qYwlqx-JLok'), 'qYwlqx-JLok');
    });

    it('debería rechazar un id con longitud incorrecta', function () {
      assert.equal(val.is_valid_yt_video('https://www.youtube.com/watch?v=abc'), false);
    });

    it('debería rechazar un dominio que solo imita a YouTube', function () {
      assert.equal(val.is_valid_yt_video('https://evilyoutube.com/watch?v=qYwlqx-JLok'), false);
    });

    it('debería rechazar un enlace con etiquetas en la URL', function () {
      assert.equal(val.is_valid_yt_video('https://www.youtube.com/watch?v=qYwlqx-JLok"><script>alert(1)</script>'), false);
    });

    it('debería devolver null al extraer el id de una URL inválida', function () {
      assert.equal(val.getYTVideoId('javascript:alert(1)'), null);
    });

    it('debería devolver cadena vacía al generar el embed de una URL inválida', function () {
      assert.equal(val.getEmbeddedCode('javascript:alert(1)'), '');
    });

  });

  describe('validateMessage: prevención de inyección de scripts', function () {

    it('debería neutralizar una etiqueta <script> en el mensaje', function () {
      var salida = validar(mensajeJson({
        nombre: 'Luz',
        mensaje: '<script>alert("XSS")</script>',
        color: '#FF0000'
      }));

      assert.equal(salida.tipo, 'texto');
      assert.equal(salida.mensaje.indexOf('<script'), -1);
      assert.equal(salida.mensaje, '&lt;script&gt;alert(&quot;XSS&quot;)&lt;/script&gt;');
    });

    it('debería neutralizar una etiqueta <img> con onerror', function () {
      var salida = validar(mensajeJson({
        nombre: 'Luz',
        mensaje: '<img src=x onerror="alert(1)">',
        color: '#FF0000'
      }));

      assert.equal(salida.mensaje.indexOf('<img'), -1);
      assert.equal(salida.mensaje, '&lt;img src=x onerror=&quot;alert(1)&quot;&gt;');
    });

    it('debería neutralizar un intento de XSS almacenado en el nombre', function () {
      var salida = validar(mensajeJson({
        nombre: '<script>alert("XSS")</script>',
        mensaje: 'hola',
        color: '#00FF00'
      }));

      assert.equal(salida.nombre.indexOf('<script'), -1);
      assert.equal(salida.nombre, '&lt;script&gt;alert(&quot;XSS&quot;)&lt;/script&gt;');
    });

    it('debería neutralizar el cierre de etiqueta en el nombre', function () {
      var salida = validar(mensajeJson({
        nombre: '</b><img src=x onerror=alert(1)>',
        mensaje: 'hola',
        color: '#00FF00'
      }));

      assert.equal(salida.nombre.indexOf('<'), -1);
      assert.equal(salida.nombre.indexOf('>'), -1);
    });

    it('debería descartar un color que intente inyectar CSS o JavaScript', function () {
      var salida = validar(mensajeJson({
        nombre: 'Luz',
        mensaje: 'hola',
        color: '#fff;background:url(javascript:alert(1))'
      }));

      assert.equal(salida.color, val.COLOR_POR_DEFECTO);
    });

    it('debería conservar un color hexadecimal válido', function () {
      var salida = validar(mensajeJson({
        nombre: 'Luz',
        mensaje: 'hola',
        color: '#1A2B3C'
      }));

      assert.equal(salida.color, '#1A2B3C');
    });

    it('debería escapar un mensaje que ni siquiera es JSON', function () {
      var salida = validar('<script>alert(1)</script>');

      assert.equal(salida.tipo, 'texto');
      assert.equal(salida.mensaje.indexOf('<script'), -1);
      assert.equal(salida.mensaje, '&lt;script&gt;alert(1)&lt;/script&gt;');
    });

    it('debería sobrevivir a entradas nulas o vacías sin lanzar excepciones', function () {
      [null, undefined, '', '   ', '{}', '[]', '42', 'true'].forEach(function (entrada) {
        assert.doesNotThrow(function () {
          var salida = validar(entrada);
          assert.equal(typeof salida.mensaje, 'string');
        });
      });
    });

    it('debería devolver un JSON válido para una batería de payloads maliciosos', function () {
      var payloads = [
        '<script>alert(1)</script>',
        '<svg/onload=alert(1)>',
        '<iframe src="javascript:alert(1)">',
        '"><script>alert(1)</script>',
        '<img src=1 onerror=alert(1)>',
        'javascript:alert(1)',
        'data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg=='
      ];

      payloads.forEach(function (payload) {
        assert.doesNotThrow(function () {
          JSON.parse(val.validateMessage(payload));
        });
      });
    });

    it('debería rechazar una URL de imagen que esconde código en la consulta', function () {
      var salida = validar(mensajeJson({
        nombre: 'Luz',
        mensaje: 'https://image.com/foto.jpg?x="><script>alert(1)</script>',
        color: '#FF0000'
      }));

      assert.equal(salida.tipo, 'texto');
      assert.equal(salida.mensaje.indexOf('<script'), -1);
    });

  });

  describe('validateMessage: detección de imágenes', function () {

    it('debería clasificar una URL .png como imagen', function () {
      var salida = validar(mensajeJson({
        nombre: 'Luz',
        mensaje: 'https://image.com/foto.png',
        color: '#FF0000'
      }));

      assert.equal(salida.tipo, 'imagen');
      assert.equal(salida.url, 'https://image.com/foto.png');
      assert.equal(salida.mensaje.indexOf('<img'), 0);
      assert.equal(salida.mensaje.indexOf('javascript:'), -1);
    });

    it('debería marcar la URL de imagen como texto si el protocolo no es http', function () {
      var salida = validar(mensajeJson({
        nombre: 'Luz',
        mensaje: 'ftp://image.com/foto.png',
        color: '#FF0000'
      }));

      assert.equal(salida.tipo, 'texto');
      assert.equal(salida.url, '');
    });

  });

  describe('validateMessage: detección de videos', function () {

    it('debería clasificar un enlace de YouTube como video_youtube', function () {
      var salida = validar(mensajeJson({
        nombre: 'Luz',
        mensaje: 'https://www.youtube.com/watch?v=qYwlqx-JLok',
        color: '#FF0000'
      }));

      assert.equal(salida.tipo, 'video_youtube');
      assert.equal(salida.videoId, 'qYwlqx-JLok');
      assert.notEqual(salida.mensaje.indexOf('https://www.youtube.com/embed/qYwlqx-JLok'), -1);
      assert.equal(salida.mensaje.indexOf('<script'), -1);
    });

    it('debería clasificar un archivo .mp4 como video', function () {
      var salida = validar(mensajeJson({
        nombre: 'Luz',
        mensaje: 'https://video.com/clip.mp4',
        color: '#FF0000'
      }));

      assert.equal(salida.tipo, 'video');
      assert.equal(salida.url, 'https://video.com/clip.mp4');
      assert.equal(salida.mensaje.indexOf('<video'), 0);
      assert.notEqual(salida.mensaje.indexOf('controls'), -1);
      assert.notEqual(salida.mensaje.indexOf('playsinline'), -1);
    });

    it('debería aceptar los formatos .webm, .ogv, .mov y .m4v', function () {
      ['webm', 'ogv', 'mov', 'm4v'].forEach(function (extension) {
        var salida = validar(mensajeJson({
          nombre: 'Luz',
          mensaje: 'https://video.com/clip.' + extension,
          color: '#FF0000'
        }));

        assert.equal(salida.tipo, 'video', extension + ' debería ser video');
      });
    });

    it('debería clasificar un enlace de YouTube con parámetros extra y extraer solo el id', function () {
      var salida = validar(mensajeJson({
        nombre: 'Luz',
        mensaje: 'https://www.youtube.com/watch?v=qYwlqx-JLok&list=PL123&t=30s',
        color: '#FF0000'
      }));

      assert.equal(salida.tipo, 'video_youtube');
      assert.equal(salida.videoId, 'qYwlqx-JLok');
      assert.equal(salida.mensaje.indexOf('&list='), -1);
      assert.equal(salida.mensaje.indexOf('&t='), -1);
    });

    it('no debería generar el tag de video para una URL inválida', function () {
      assert.equal(val.getVideoTag('javascript:alert(1)'), '');
      assert.equal(val.getVideoTag('https://video.com/clip.exe'), '');
    });

    it('debería preferir imagen sobre video según la extensión', function () {
      var imagen = validar(mensajeJson({ nombre: 'Luz', mensaje: 'https://x.com/a.jpg', color: '#FF0000' }));
      var video = validar(mensajeJson({ nombre: 'Luz', mensaje: 'https://x.com/a.mp4', color: '#FF0000' }));

      assert.equal(imagen.tipo, 'imagen');
      assert.equal(video.tipo, 'video');
    });

    it('debería escapar el ampersand de una URL con parámetros dentro del tag', function () {
      var salida = validar(mensajeJson({
        nombre: 'Luz',
        mensaje: 'https://image.com/foto.jpg?w=100&h=100',
        color: '#FF0000'
      }));

      assert.equal(salida.tipo, 'imagen');
      assert.notEqual(salida.mensaje.indexOf('&amp;'), -1);
    });

    it('debería escapar el HTML en un mensaje de texto normal', function () {
      var salida = validar(mensajeJson({
        nombre: 'Luz',
        mensaje: 'Hola a todos & bienvenidos',
        color: '#FF0000'
      }));

      assert.equal(salida.tipo, 'texto');
      assert.equal(salida.mensaje, 'Hola a todos &amp; bienvenidos');
    });

  });

  describe('Endurecimiento de URLs', function () {

    it('debería rechazar una URL con credenciales incrustadas', function () {
      assert.equal(val.is_valid_url_image('https://usuario:clave@image.com/foto.png'), false);
      assert.equal(val.is_valid_video_url('https://usuario:clave@video.com/clip.mp4'), false);
      assert.equal(val.is_valid_yt_video('https://usuario:clave@youtube.com/watch?v=qYwlqx-JLok'), false);
    });

    it('debería clasificar como texto una URL con credenciales incrustadas', function () {
      var salida = validar(mensajeJson({
        nombre: 'Luz',
        mensaje: 'https://usuario:clave@image.com/foto.png',
        color: '#FF0000'
      }));

      assert.equal(salida.tipo, 'texto');
      assert.equal(salida.url, '');
    });

    it('debería aceptar el esquema en mayúsculas', function () {
      assert.equal(val.is_valid_url_image('HTTPS://IMAGE.COM/FOTO.PNG'), true);
    });

    it('debería rechazar una URL relativa al protocolo', function () {
      assert.equal(val.is_valid_url_image('//image.com/foto.png'), false);
    });

    it('debería rechazar los esquemas file y ftp', function () {
      assert.equal(val.is_valid_url_image('file:///C:/foto.png'), false);
      assert.equal(val.is_valid_url_image('ftp://image.com/foto.png'), false);
    });

    it('debería rechazar una URL que supera el largo máximo', function () {
      var larga = 'https://image.com/' + new Array(2050).join('a') + '.png';
      assert.equal(val.is_valid_url_image(larga), false);
    });

    it('debería rechazar una URL con tabulaciones o saltos de línea', function () {
      assert.equal(val.is_valid_url_image('https://image.com/a\tb.png'), false);
      assert.equal(val.is_valid_url_image('https://image.com/a\nb.png'), false);
    });

  });

  describe('Limpieza de caracteres invisibles', function () {

    it('debería eliminar caracteres de control del texto', function () {
      assert.equal(val.limpiarTexto('hola\u0000mundo\u001F!'), 'holamundo!');
    });

    it('debería eliminar marcadores bidireccionales', function () {
      assert.equal(val.limpiarTexto('normal\u202Eotra'), 'normalotra');
      assert.equal(val.limpiarTexto('a\u2066b\u2069c'), 'abc');
    });

    it('debería conservar tildes y eñes', function () {
      assert.equal(val.limpiarTexto('Programación en español'), 'Programación en español');
    });

    it('debería limpiar el nombre y el mensaje antes de escaparlos', function () {
      var salida = validar(mensajeJson({
        nombre: 'Lu\u0000z\u202E',
        mensaje: 'hola\u0000 mundo',
        color: '#FF0000'
      }));

      assert.equal(salida.nombre, 'Luz');
      assert.equal(salida.mensaje, 'hola mundo');
    });

  });

  describe('Integridad del JSON y límites', function () {

    it('debería mostrar como texto un mensaje de 2000 caracteres y no el JSON crudo', function () {
      var largo = new Array(2001).join('a');
      var salida = validar(mensajeJson({
        nombre: 'Luz',
        mensaje: largo,
        color: '#FF0000'
      }));

      assert.equal(salida.tipo, 'texto');
      assert.equal(salida.mensaje.length, val.MAX_LONGITUD_MENSAJE);
      assert.equal(salida.mensaje.indexOf('"nombre"'), -1);
      assert.equal(salida.mensaje.indexOf('{'), -1);
    });

    it('debería recortar el nombre a 50 caracteres', function () {
      var salida = validar(mensajeJson({
        nombre: new Array(200).join('n'),
        mensaje: 'hola',
        color: '#FF0000'
      }));

      assert.equal(salida.nombre.length, val.MAX_LONGITUD_NOMBRE);
    });

    it('debería ignorar un mensaje que llega como objeto o arreglo', function () {
      var objeto = validar('{"nombre":"Luz","mensaje":{"a":1},"color":"#FF0000"}');
      var arreglo = validar('{"nombre":"Luz","mensaje":["a","b"],"color":"#FF0000"}');

      assert.equal(objeto.mensaje, '');
      assert.equal(arreglo.mensaje, '');
    });

    it('no debería permitir contaminación de prototipos', function () {
      validar('{"__proto__":{"contaminado":true},"nombre":"Luz","mensaje":"hola","color":"#FF0000"}');
      validar('{"constructor":{"prototype":{"contaminado":true}},"mensaje":"hola"}');

      assert.equal({}.contaminado, undefined);
      assert.equal(Object.prototype.contaminado, undefined);
    });

    it('debería devolver siempre las mismas claves en la respuesta', function () {
      var salida = validar(mensajeJson({ nombre: 'Luz', mensaje: 'hola', color: '#FF0000' }));

      assert.deepEqual(Object.keys(salida).sort(), ['color', 'mensaje', 'nombre', 'tipo', 'url', 'videoId']);
    });

    it('debería soportar un JSON de entrada de más de 10 000 caracteres sin lanzar excepciones', function () {
      var enorme = new Array(12001).join('x');

      assert.doesNotThrow(function () {
        var salida = validar(enorme);
        assert.equal(salida.mensaje.length, val.MAX_LONGITUD_MENSAJE);
      });
    });

  });

  describe('Cliente del chat (index.html)', function () {

    var html = fs.readFileSync(path.join(__dirname, '..', 'index.html'), 'utf8');

    it('no debería conservar el render antiguo que inyectaba el mensaje crudo', function () {
      assert.equal(html.indexOf('mensajeDisplay'), -1);
    });

    it('debería construir el contenido con nodos del DOM', function () {
      assert.notEqual(html.indexOf('nodoContenido'), -1);
      assert.notEqual(html.indexOf("$('<img>')"), -1);
      assert.notEqual(html.indexOf("$('<video>')"), -1);
      assert.notEqual(html.indexOf("$('<iframe>')"), -1);
    });

    it('debería validar el color antes de aplicarlo al estilo', function () {
      assert.notEqual(html.indexOf('colorSeguro'), -1);
    });

  });

});
