// Решения страницы, которые не зависят от разметки: их проверяет тест через node.
"use strict";

var TrassaLogic = {
  // adopt решает, что показать в редакторе, когда с роутера пришёл действующий текст правил.
  // Несохранённая правка не пропадает: после повторного входа или перезапуска страницы в редакторе
  // остаётся то, что набрал человек. Возвращает {editor, saved, note}.
  adopt: function (editor, saved, server) {
    if (editor === saved || editor === server) return { editor: server, saved: server, note: "" };
    if (server === saved) return { editor: editor, saved: server, note: "Несохранённая правка осталась в редакторе." };
    return {
      editor: editor, saved: server,
      note: "Пока вас не было, правила на роутере изменились. Ваша правка осталась в редакторе; " +
        "«Отменить правку» покажет действующий текст."
    };
  }
};
