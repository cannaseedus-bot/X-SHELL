export function renderGraph(svg, flowGraph) {
  svg.innerHTML = "";

  const nodeSpacing = 150;
  const nodeY = 200;
  const nodeById = new Map();

  flowGraph.nodes.forEach((node, index) => {
    const x = 100 + index * nodeSpacing;
    nodeById.set(node.id, { x, y: nodeY, node });
  });

  flowGraph.edges.forEach(edge => {
    const from = nodeById.get(edge.from);
    const to = nodeById.get(edge.to);
    if (!from || !to) {
      return;
    }

    const line = document.createElementNS("http://www.w3.org/2000/svg", "line");
    line.setAttribute("x1", from.x);
    line.setAttribute("y1", from.y);
    line.setAttribute("x2", to.x);
    line.setAttribute("y2", to.y);
    line.setAttribute("stroke", "#5e5e5e");
    svg.appendChild(line);
  });

  flowGraph.nodes.forEach(node => {
    const { x, y } = nodeById.get(node.id);

    const circle = document.createElementNS("http://www.w3.org/2000/svg", "circle");
    circle.setAttribute("cx", x);
    circle.setAttribute("cy", y);
    circle.setAttribute("r", 30);
    circle.setAttribute("fill", "#222");
    circle.setAttribute("stroke", "#eee");

    const label = document.createElementNS("http://www.w3.org/2000/svg", "text");
    label.setAttribute("x", x);
    label.setAttribute("y", y + 5);
    label.setAttribute("text-anchor", "middle");
    label.setAttribute("fill", "#eee");
    label.textContent = node.id;

    const weight = document.createElementNS("http://www.w3.org/2000/svg", "text");
    weight.setAttribute("x", x);
    weight.setAttribute("y", y + 45);
    weight.setAttribute("text-anchor", "middle");
    weight.setAttribute("fill", "#8ecaff");
    weight.textContent = "w=" + node.weight;

    svg.appendChild(circle);
    svg.appendChild(label);
    svg.appendChild(weight);
  });
}
