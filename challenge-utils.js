// Challenge Mode Utilities
// Shared across all games in challenge sequence

var ChallengeMode={
  isActive:function(){
    return !!sessionStorage.getItem('challenge-active');
  },
  
  getLevel:function(){
    return parseInt(sessionStorage.getItem('challenge-level'))||1;
  },
  
  getGames:function(){
    var games=sessionStorage.getItem('challenge-games');
    return games?JSON.parse(games):[];
  },
  
  getCurrentGameIndex:function(){
    return parseInt(sessionStorage.getItem('challenge-idx'))||0;
  },
  
  getCurrentGame:function(){
    var games=this.getGames();
    var idx=this.getCurrentGameIndex();
    return games[idx]||null;
  },
  
  getNextGame:function(){
    var games=this.getGames();
    var idx=this.getCurrentGameIndex();
    return games[idx+1]||null;
  },
  
  getTotalScore:function(){
    return parseInt(sessionStorage.getItem('challenge-score'))||0;
  },
  
  addScore:function(points){
    var current=this.getTotalScore();
    var total=current+points;
    sessionStorage.setItem('challenge-score',total);
    return total;
  },
  
  isLastGame:function(){
    var games=this.getGames();
    var idx=this.getCurrentGameIndex();
    return idx>=games.length-1;
  },
  
  advanceGame:function(){
    var idx=this.getCurrentGameIndex();
    sessionStorage.setItem('challenge-idx',idx+1);
  },
  
  onGameOver:function(gameName, score){
    if(!this.isActive())return;
    
    this.addScore(score);
    
    if(this.isLastGame()){
      // Challenge complete!
      var totalScore=this.getTotalScore();
      sessionStorage.setItem('challenge-complete','1');
      sessionStorage.setItem('challenge-final-score',totalScore);
      sessionStorage.setItem('challenge-final-game',gameName);
      window.location.href='/challenge-complete.html';
    }else{
      // Go to next game
      this.advanceGame();
      var nextGame=this.getNextGame();
      if(nextGame){
        sessionStorage.setItem('challenge-current-game',nextGame.id);
        window.location.href='/'+nextGame.pageId+'.html?challenge='+this.getLevel();
      }
    }
  },
  
  onGameFail:function(gameName, score){
    if(!this.isActive())return;
    
    this.addScore(score);
    
    sessionStorage.setItem('challenge-failed-game',gameName);
    sessionStorage.setItem('challenge-final-score',score);
    window.location.href='/challenge-failed.html';
  }
};
