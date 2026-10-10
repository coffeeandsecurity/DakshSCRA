(function () {
  function revealAnchor() {
    var target = document.getElementById(decodeURIComponent(location.hash.slice(1)));
    if (!target) return;
    for (var node=target; node; node=node.parentElement) {
      if (node.tagName==='DETAILS') node.open=true;
      node.hidden=false;
    }
  }
  window.addEventListener('hashchange', revealAnchor);
  revealAnchor();
  document.querySelectorAll('[data-report-expand],[data-report-collapse]').forEach(function(button){
    button.addEventListener('click',function(){
      var id=button.dataset.reportExpand||button.dataset.reportCollapse;
      document.getElementById(id).querySelectorAll('details').forEach(function(item){item.open=Boolean(button.dataset.reportExpand);});
    });
  });
  document.querySelectorAll('[data-report-search]').forEach(function(input){
    input.addEventListener('input',function(){
      var query=input.value.toLowerCase();
      document.getElementById(input.dataset.reportSearch).querySelectorAll('.report-entry').forEach(function(item){item.hidden=!item.textContent.toLowerCase().includes(query);});
    });
  });
  var beforePrint=[];
  window.addEventListener('beforeprint',function(){
    beforePrint=Array.from(document.querySelectorAll('details')).map(function(item){var state=[item,item.open,item.hidden];item.open=true;item.hidden=false;return state;});
  });
  window.addEventListener('afterprint',function(){beforePrint.forEach(function(state){state[0].open=state[1];state[0].hidden=state[2];});});
})();
