(function() {
  var style = getComputedStyle(document.documentElement);
  var accent = style.getPropertyValue('--accent').trim();
  var accent2 = style.getPropertyValue('--accent2').trim();
  var accent3 = style.getPropertyValue('--accent3').trim();
  var accent4 = style.getPropertyValue('--accent4').trim();
  var ink = style.getPropertyValue('--ink').trim();
  var muted = style.getPropertyValue('--muted').trim();
  var rule = style.getPropertyValue('--rule').trim();
  var bg2 = style.getPropertyValue('--bg2').trim();

  // --- Chart: Radar - Defense Coverage ---
  var radarChart = echarts.init(document.getElementById('chart-radar'), null, { renderer: 'svg' });
  radarChart.setOption({
    tooltip: {
      appendToBody: true,
      trigger: 'item'
    },
    animation: false,
    radar: {
      indicator: [
        { name: 'CC攻击防御', max: 100 },
        { name: 'SQL注入/XSS防御', max: 100 },
        { name: 'Webshell查杀', max: 100 },
        { name: '恶意扫描器封锁', max: 100 },
        { name: '区域访问控制', max: 100 },
        { name: 'UA/IP黑白名单', max: 100 },
        { name: '可视化运维', max: 100 },
        { name: '规则自定义能力', max: 100 }
      ],
      center: ['50%', '50%'],
      radius: '70%',
      axisName: {
        color: ink,
        fontSize: 11
      },
      splitArea: {
        areaStyle: {
          color: [bg2 + '80', bg2 + '40']
        }
      },
      splitLine: {
        lineStyle: {
          color: rule
        }
      }
    },
    series: [{
      type: 'radar',
      data: [
        {
          value: [92, 95, 85, 88, 90, 95, 93, 96],
          name: '覆盖度评分',
          areaStyle: {
            color: accent + '30'
          },
          lineStyle: {
            color: accent,
            width: 2
          },
          itemStyle: {
            color: accent
          }
        }
      ]
    }]
  });
  window.addEventListener('resize', function() { radarChart.resize(); });

  // --- Chart: Bar - Interception Capability ---
  var barChart = echarts.init(document.getElementById('chart-bar'), null, { renderer: 'svg' });
  barChart.setOption({
    tooltip: {
      appendToBody: true,
      trigger: 'axis',
      axisPointer: { type: 'shadow' }
    },
    animation: false,
    grid: {
      left: '3%',
      right: '4%',
      bottom: '3%',
      containLabel: true
    },
    xAxis: {
      type: 'value',
      axisLabel: { color: muted, fontSize: 11 },
      axisLine: { lineStyle: { color: rule } },
      splitLine: { lineStyle: { color: rule + '60' } }
    },
    yAxis: {
      type: 'category',
      data: ['CC攻击', 'SQL注入', 'XSS/XSRF', 'Webshell上传', '恶意扫描器', '非浏览器爬虫', '异地/境外访问', '敏感词/违禁词'],
      axisLabel: { color: ink, fontSize: 11 },
      axisLine: { lineStyle: { color: rule } },
      axisTick: { show: false }
    },
    series: [{
      type: 'bar',
      data: [
        { value: 92, itemStyle: { color: accent } },
        { value: 95, itemStyle: { color: accent2 } },
        { value: 95, itemStyle: { color: accent2 } },
        { value: 85, itemStyle: { color: accent4 } },
        { value: 88, itemStyle: { color: accent3 } },
        { value: 80, itemStyle: { color: '#7c3aed' } },
        { value: 90, itemStyle: { color: accent3 } },
        { value: 82, itemStyle: { color: accent4 } }
      ],
      barWidth: '60%',
      label: {
        show: true,
        position: 'right',
        color: muted,
        fontSize: 11,
        formatter: function(p) { return p.value + '%'; }
      }
    }]
  });
  window.addEventListener('resize', function() { barChart.resize(); });
})();