set key vertical maxrows 2 width 0

set xlabel "Number of Replicas"
set ylabel "Throughput (ops/sec)"
set yrange [10:400]
set ytic format "%gK"
set xtics 1,3,13


plot \
     "10.dat" using ($1*3+1):($2/1000) title "Neo-HM" \
     with linespoints lt 4 pointsize 1.7, \
     "11.dat" using ($1*3+1):($2/1000) title "Neo-PK" \
     with linespoints lt 2, 
     