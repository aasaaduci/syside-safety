package MotionControl {
doc /* Motion control subsystem for guidance, navigation, and control */
private import ScalarValues::*;
private import Localization::*;
private import Perception::*;
private import CollaborativeAutonomy::*;
private import GARC_Model::*;

part def MotionControlSubsystem {
    doc /* Executes trajectory following and collision avoidance */
    in positionIn : PositionPort;
    in obstacleDataIn : Perception::ObstacleDataPort;
    in missionCommandIn;
    out actuationOut : ActuationInterface;
}
}
