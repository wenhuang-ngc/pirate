#pragma once
#include "channel.h"
#include "pnt_data.h"
#include <iostream>

class OwnShip
{
  // Channel to transmit position updates to
  Sender<Position> _c;
  Track _track;
  int _frequency;
  int _cycle;
  int _cnt;
public:
  OwnShip(const Sender<Position>& c, int rate = 1)
    : _c(c),
      _frequency(rate),
     _cycle(static_cast<int> (((1.0 / _frequency) / (sleep_msec / 1000)))),
     _cnt(0) {
    };

  ~OwnShip() {};

  Position getPosition() { return _track._pos; }
  Track getTracking() { return _track; }

  void onGpsPositionChange(const Position& p) {
    setPosition(p);
    if (_cycle != 0 && 0 == ++_cnt % _cycle) {
      print_track();
      _c(_track._pos);
    }
  }

  void print_track()
  {
    print([this](std::ostream& o) {
      o << "---UAV TRACK ---" << std::endl
	      << " x=" << _track._pos._x << std::endl
	      << " y=" << _track._pos._y << std::endl
	      << " z=" << _track._pos._z << std::endl << std::endl;
    });
  }
protected:
  void setPosition(Position const& p) { _track._pos = p; }
  void setVelocity(Velocity const& v) { _track._v = v; }
};