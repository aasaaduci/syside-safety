package Perception {
doc /* Perception subsystem for environment sensing */
private import ScalarValues::*;
private import SI::*;

part def PerceptionSubsystem {
    doc /* Aggregates sensor data to detect obstacles */
    out obstacleDataOut : ObstacleDataPort;
}

port def ObstacleDataPort {
    attribute obstacleSummary : String;
    attribute timestamp : TimeUnit;
}
}
