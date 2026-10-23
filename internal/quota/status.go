// Package quota keeps a sliding-window message count per upstream and persists
// it to a state file. The quota is soft: it never blocks mail.
package quota

// Status is a point-in-time view of one upstream's quota, used by metrics.
type Status struct {
	Upstream string
	Used     int64 // messages inside the window
	Limit    int64
}

// Percent returns Used/Limit*100 rounded to 2 decimals; it can exceed 100.
// It returns 0 when Limit <= 0.
func (s Status) Percent() float64 {
	if s.Limit <= 0 {
		return 0
	}
	p := float64(s.Used) / float64(s.Limit) * 100
	return float64(int64(p*100+0.5)) / 100
}
