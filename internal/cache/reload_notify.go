package cache

import "sync"

type Notify struct {
	mu  sync.Mutex
	ch  chan struct{}
}

func NewNotify() *Notify {
	n := &Notify{ch: make(chan struct{}, 1)}
	return n
}

func (n *Notify) Signal() {
	n.mu.Lock()
	select {
	case n.ch <- struct{}{}:
	default:
	}
	n.mu.Unlock()
}

func (n *Notify) Channel() <-chan struct{} {
	return n.ch
}
